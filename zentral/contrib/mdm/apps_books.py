from collections import OrderedDict
from itertools import islice
import logging
import threading
from django.core.cache import cache
from django.db import transaction
from django.urls import reverse
from django.utils.functional import SimpleLazyObject
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from urllib.parse import urljoin
from base.utils import deployment_info
from zentral.conf import settings
from zentral.core.events.base import EventMetadata
from .commands.install_application import InstallApplication
from .events import (AssetCreatedEvent, AssetUpdatedEvent,
                     DeviceAssignmentCreatedEvent, DeviceAssignmentDeletedEvent,
                     ServerTokenAssetCreatedEvent, ServerTokenAssetUpdatedEvent)
from .incidents import MDMAssetAvailabilityIncident
from .models import (Asset, ArtifactType, ArtifactVersion, DeviceAssignment,
                     EnrolledDevice, ServerToken, ServerTokenAsset)


logger = logging.getLogger("zentral.contrib.mdm.apps_books")


# API client


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, default_timeout, retries):
        self.default_timeout = default_timeout
        super().__init__(
            max_retries=Retry(
                total=retries + 1,
                backoff_factor=1,
                status_forcelist=[500, 502, 503, 504]
            )
        )

    def send(self, *args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(*args, **kwargs)


class MDMConflictError(Exception):
    pass


class FetchedDataUpdatedError(Exception):
    pass


class AppsBooksClient:
    base_url = "https://vpp.itunes.apple.com/mdm/v2/"
    timeout = 5
    retries = 2

    def __init__(
        self, token,
        notification_auth_token_id=None, notification_auth_token=None,
        location_name=None,
        platform=None
    ):
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": deployment_info.user_agent,
            "Authorization": f"Bearer {token}",
        })
        adapter = CustomHTTPAdapter(self.timeout, self.retries)
        self.session.mount("https://", adapter)
        self.notification_auth_token_id = None
        if notification_auth_token_id:
            self.notification_auth_token_id = str(notification_auth_token_id)
        self.notification_auth_token = notification_auth_token
        self.location_name = location_name
        self.platform = platform or "enterprisestore"
        self._service_config = None

    def close(self):
        self.session.close()

    @classmethod
    def from_server_token(cls, server_token):
        return cls(server_token.get_token(),
                   server_token.notification_auth_token_id,
                   server_token.get_notification_auth_token(),
                   server_token.location_name,
                   server_token.platform)

    def make_request(self, path, **kwargs):
        url = urljoin(self.base_url, path)
        verify_mdm_info = kwargs.pop("verify_mdm_info", False)
        if "json" in kwargs:
            method = self.session.post
        else:
            method = self.session.get
        resp = method(url, **kwargs)
        resp.raise_for_status()
        response = resp.json()
        if (
            verify_mdm_info
            and self.notification_auth_token_id is not None
            and response.get("mdmInfo", {}).get("id") != self.notification_auth_token_id
        ):
            logger.error("Location %s: bad MDM id", self.location_name)
            raise MDMConflictError
        return response

    # client config

    def get_client_config(self):
        return self.make_request("client/config")

    def update_client_config(self):
        assert self.notification_auth_token_id is not None and self.notification_auth_token is not None
        fqdn = settings["api"]["fqdn"]
        return self.make_request(
            "client/config",
            json={
                "mdmInfo": {
                    "id": self.notification_auth_token_id,
                    "metadata": fqdn,
                    "name": "Zentral"
                },
                "notificationTypes": ["ASSET_MANAGEMENT", "ASSET_COUNT"],
                "notificationUrl": "https://{}{}".format(
                    #zentral_settings["api"]["fqdn"],
                    "while-bird-headquarters-filters.trycloudflare.com",
                    reverse("mdm:notify_server_token", args=(self.notification_auth_token_id,))
                ),
                "notificationAuthToken": self.notification_auth_token,
            }
        )

    # service config

    def get_service_config(self):
        if not self._service_config:
            self._service_config = self.make_request("service/config", verify_mdm_info=False)
        return self._service_config

    # assets

    def get_asset(self, adam_id, pricing_param):
        response = self.make_request("assets", params={"adamId": adam_id, "pricingParam": pricing_param})
        try:
            return response["assets"][0]
        except IndexError:
            pass

    def iter_assets(self):
        current_version_id = None
        current_page = 0
        while True:
            logger.debug("Location %s: fetch asset page %s", self.location_name, current_page)
            response = self.make_request("assets", params={"pageIndex": current_page})
            version_id = response["versionId"]
            if current_version_id is None:
                current_version_id = version_id
            elif current_version_id != version_id:
                logger.error("Writes occured to the assets while iterating over them")
                raise FetchedDataUpdatedError
            for asset in response.get("assets", []):
                yield asset
            try:
                next_page = int(response["nextPageIndex"])
            except KeyError:
                logger.debug("Location %s: last asset page", self.location_name)
                break
            else:
                if next_page != current_page + 1:
                    logger.error("Location %s: nextPageIndex != current page + 1", self.location_name)
                    # should never happen
                    raise ValueError
                current_page = next_page

    def get_asset_metadata(self, adam_id):
        service_config = self.get_service_config()
        url = service_config.get("urls", {}).get("contentMetadataLookup")
        if not url:
            logger.error("Location %s: missing or empty contentMetadataLookup", self.location_name)
            return
        resp = requests.get(
            url,
            params={"version": 2,
                    "p": "mdm-lockup",  # TODO: Really?
                    "caller": "MDM",
                    "platform": self.platform,
                    "cc": "us",
                    "l": "en",
                    "id": adam_id},
            cookies={"itvt": self.token}
        )
        if resp:
            response = resp.json()
            return response.get("results", {}).get(adam_id)
        else:
            logger.error("Location %s: could not get asset %s metadata", self.location_name, adam_id)

    # assignments

    def iter_asset_device_assignments(self, adam_id, pricing_param):
        current_version_id = None
        current_page = 0
        while True:
            logger.debug("Location %s: fetch assignment page %s", self.location_name, current_page)
            response = self.make_request("assignments", params={"adamId": adam_id, "pageIndex": current_page})
            version_id = response["versionId"]
            if current_version_id is None:
                current_version_id = version_id
            elif current_version_id != version_id:
                logger.error("Writes occured to the assignments while iterating over them")
                raise FetchedDataUpdatedError
            for asset in response.get("assignments", []):
                if asset["pricingParam"] != pricing_param:
                    continue
                serial_number = asset.get("serialNumber")
                if not serial_number:
                    logger.error("Location %s: asset %s/%s with user assignments",
                                 self.location_name, adam_id, pricing_param)
                else:
                    yield serial_number
            try:
                next_page = int(response["nextPageIndex"])
            except KeyError:
                logger.debug("Location %s: last assignment page", self.location_name)
                break
            else:
                if next_page != current_page + 1:
                    logger.error("Location %s: nextPageIndex != current page + 1", self.location_name)
                    # should never happen
                    raise ValueError
                current_page = next_page

    def post_device_association(self, serial_number, asset):
        return self.make_request(
            "assets/associate",
            json={
                "assets": [{
                    "adamId": asset.adam_id,
                    "pricingParam": asset.pricing_param,
                }],
                "serialNumbers": [serial_number]
            },
        )

    def post_device_disassociation(self, serial_number, asset):
        return self.make_request(
            "assets/disassociate",
            json={
                "assets": [{
                    "adamId": asset.adam_id,
                    "pricingParam": asset.pricing_param,
                }],
                "serialNumbers": [serial_number]
            },
        )


# server token cache


class ServerTokenCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._server_tokens = {}
        self._known_bad = OrderedDict()
        self._known_bad_capacity = 1024

    def _is_known_bad(self, notification_auth_token_id):
        test = notification_auth_token_id in self._known_bad
        if test:
            self._known_bad.move_to_end(notification_auth_token_id)
        return test

    def _add_known_bad(self, notification_auth_token_id):
        if len(self._known_bad) >= self._none_bad_capacity:
            self._known_bad.popitem(last=False)
        self._known_bad[notification_auth_token_id] = 1
        self._known_bad.move_to_end(notification_auth_token_id)

    def get(self, notification_auth_token_id):
        with self._lock:
            try:
                return self._server_tokens[notification_auth_token_id]
            except KeyError:
                server_token = None
                client = None
                notification_auth_token = None
                if not self._is_known_bad(notification_auth_token_id):
                    try:
                        server_token = ServerToken.objects.get(notification_auth_token_id=notification_auth_token_id)
                    except ServerToken.DoesNotExist:
                        self._add_known_bad(notification_auth_token_id)
                    else:
                        client = AppsBooksClient.from_server_token(server_token)
                        notification_auth_token = server_token.get_notification_auth_token()
                        # remove other cache entry for this server
                        for nati, (st, cli, nat) in list(self._server_tokens.items()):
                            if st == server_token:
                                cli.close()
                                del self._server_tokens[nati]
                                break
                        self._server_tokens[notification_auth_token_id] = (
                            server_token, client, notification_auth_token
                        )
                return server_token, client, notification_auth_token


server_token_cache = SimpleLazyObject(lambda: ServerTokenCache())


#
# on-the-fly assignment
#
# Instead of sending the InstallApplication command directly
# a device asset association is triggered. The cache is used
# when the assignment notification is received to check if there
# is an artifact version to install.
# The cache is also used to avoid triggering the association too often.
#


def enrolled_device_asset_association_cache_key(server_token, serial_number, adam_id, pricing_param):
    return f"apps_books_edaack|{server_token.pk}|{serial_number}|{adam_id}|{pricing_param}"


def ensure_enrolled_device_asset_association(enrolled_device, asset):
    server_token = enrolled_device.server_token
    if not server_token:
        logger.error("enrolled device %s has no server token", enrolled_device.serial_number)
        return False
    serial_number = enrolled_device.serial_number
    # no need for a lock, it will eventually converge
    qs = DeviceAssignment.objects.filter(
        serial_number=serial_number,
        server_token_asset__asset=asset,
        server_token_asset__server_token=server_token
    )
    if qs.count():
        return True
    cache_key = enrolled_device_asset_association_cache_key(
        server_token, serial_number, asset.adam_id, asset.pricing_param
    )
    if cache.add(cache_key, enrolled_device.pk, timeout=3600):  # TODO hard-coded
        _, client, _ = server_token_cache.get(server_token.notification_auth_token_id)
        ok = False
        try:
            response = client.post_device_association(serial_number, asset)
        except Exception:
            logger.exception("Could not post device assignment %s/%s => %s",
                             asset.adam_id, asset.pricing_param, serial_number)
        else:
            event_id = response.get("eventId")
            if event_id:
                ok = True
        if not ok:
            cache.delete(cache_key)
    return False


def queue_install_application_command_if_necessary(server_token, serial_number, adam_id, pricing_param):
    cache_key = enrolled_device_asset_association_cache_key(
        server_token, serial_number, adam_id, pricing_param
    )
    enrolled_device_id = cache.get(cache_key)
    if enrolled_device_id:
        cache.delete(cache_key)
        try:
            enrolled_device = (
                EnrolledDevice.objects.select_related("blueprint").get(pk=enrolled_device_id)
            )
        except EnrolledDevice.DoesNotExist:
            logger.error("location %s asset %s/%s: cannot find enrolled device %s",
                         server_token.location_name, adam_id, pricing_param, enrolled_device_id)
        else:
            # find the latest artifact version to install for this asset
            for artifact_version in ArtifactVersion.objects.next_to_install(enrolled_device, fetch_all=True):
                if (
                    artifact_version.artifact.type == ArtifactType.StoreApp.name
                    and artifact_version.store_app.asset.adam_id == adam_id
                    and artifact_version.store_app.asset.pricing_param == pricing_param
                ):
                    InstallApplication.create_for_device(
                        enrolled_device, artifact_version, queue=True
                    )
                    break


def clear_on_the_fly_assignment_cache(server_token, serial_number, adam_id, pricing_param, reason):
    cache_key = enrolled_device_asset_association_cache_key(
        server_token, serial_number, adam_id, pricing_param
    )
    if cache.delete(cache_key):
        logger.error("Location %s asset %s/%s: on-the-fly assignment canceled for device %s, %s",
                     server_token.location_name, adam_id, pricing_param, serial_number, reason)


# assets & assignments sync


def _update_or_create_asset(adam_id, pricing_param, defaults, notification_id, collected_objects):
    asset, created = Asset.objects.select_for_update().get_or_create(
        adam_id=adam_id,
        pricing_param=pricing_param,
        defaults=defaults
    )
    collected_objects["asset"] = asset
    if created:
        payload = asset.serialize_for_event(keys_only=False)
        if notification_id:
            payload["notification_id"] = notification_id
        yield AssetCreatedEvent(EventMetadata(), payload)
    else:
        updated = False
        for attr, new_val in defaults.items():
            old_val = getattr(asset, attr)
            if old_val != new_val:
                setattr(asset, attr, new_val)
                updated = True
        if updated:
            asset.save()
            payload = asset.serialize_for_event(keys_only=False)
            if notification_id:
                payload["notification_id"] = notification_id
            yield AssetUpdatedEvent(EventMetadata(), payload)


def _get_server_token_asset_event_metadata(server_token_asset):
    incident_updates = []
    incident_update_severity = server_token_asset.get_availability_incident_severity()
    if incident_update_severity is not None:
        incident_updates.append(
            MDMAssetAvailabilityIncident.build_incident_update(
                server_token_asset, incident_update_severity
            )
        )
    return EventMetadata(incident_updates=incident_updates)


def _update_or_create_server_token_asset(server_token, defaults, notification_id, collected_objects):
    asset = collected_objects["asset"]
    server_token_asset, created = ServerTokenAsset.objects.select_for_update().get_or_create(
        server_token=server_token,
        asset=asset,
        defaults=defaults
    )
    collected_objects["server_token_asset"] = server_token_asset
    if created:
        payload = server_token_asset.serialize_for_event(
            keys_only=False, server_token=server_token, asset=asset
        )
        if notification_id:
            payload["notification_id"] = notification_id
        yield ServerTokenAssetCreatedEvent(
            _get_server_token_asset_event_metadata(server_token_asset),
            payload
        )
    else:
        updated = False
        for attr, new_val in defaults.items():
            old_val = getattr(server_token_asset, attr)
            if old_val != new_val:
                setattr(server_token_asset, attr, new_val)
                updated = True
        if updated:
            server_token_asset.save()
            payload = server_token_asset.serialize_for_event(
                    keys_only=False, server_token=server_token, asset=asset
            )
            if notification_id:
                payload["notification_id"] = notification_id
            yield ServerTokenAssetUpdatedEvent(
                _get_server_token_asset_event_metadata(server_token_asset),
                payload
            )


def _update_assignments(server_token, all_serial_numbers, notification_id, collected_objects):
    asset = collected_objects["asset"]
    server_token_asset = collected_objects["server_token_asset"]
    existing_serial_numbers = set(server_token_asset.deviceassignment_set.values_list("serial_number", flat=True))
    if all_serial_numbers == existing_serial_numbers:
        return

    # prepare common event payload
    payload = server_token_asset.serialize_for_event(keys_only=False, server_token=server_token, asset=asset)
    if notification_id:
        payload["notification_id"] = notification_id

    # prune assignments
    removed_serial_numbers = existing_serial_numbers - all_serial_numbers
    if removed_serial_numbers:
        DeviceAssignment.objects.filter(server_token_asset=server_token_asset,
                                        serial_number__in=removed_serial_numbers).delete()
        for serial_number in removed_serial_numbers:
            yield DeviceAssignmentDeletedEvent(EventMetadata(machine_serial_number=serial_number), payload)

    # add missing assignments
    added_serial_numbers = all_serial_numbers - existing_serial_numbers
    if not added_serial_numbers:
        return
    batch_size = 1000  # TODO: hard-coded
    assignments_to_create = (DeviceAssignment(server_token_asset=server_token_asset,
                                              serial_number=serial_number)
                             for serial_number in added_serial_numbers)
    while True:
        batch = list(islice(assignments_to_create, batch_size))
        if not batch:
            break
        DeviceAssignment.objects.bulk_create(batch, batch_size)
    for serial_number in added_serial_numbers:
        yield DeviceAssignmentCreatedEvent(EventMetadata(machine_serial_number=serial_number), payload)


def _sync_asset_d(server_token, client, asset_d, notification_id=None):
    adam_id = asset_d["adamId"]
    pricing_param = asset_d["pricingParam"]

    asset_defaults = {
        "product_type": Asset.ProductType(asset_d["productType"]),
        "device_assignable": asset_d["deviceAssignable"],
        "revocable": asset_d["revocable"],
        "supported_platforms": asset_d["supportedPlatforms"],
    }
    metadata = client.get_asset_metadata(adam_id)
    if metadata:
        asset_defaults["metadata"] = metadata
        asset_defaults["name"] = metadata.get("name")
        asset_defaults["bundle_id"] = metadata.get("bundleId")

    server_token_asset_defaults = {
        "assigned_count": asset_d["assignedCount"],
        "available_count": asset_d["availableCount"],
        "retired_count": asset_d["retiredCount"],
        "total_count": asset_d["totalCount"],
    }

    all_serial_numbers = set(client.iter_asset_device_assignments(adam_id, pricing_param))

    with transaction.atomic():
        collected_objects = {}

        # asset
        yield from _update_or_create_asset(
            adam_id, pricing_param,
            asset_defaults,
            notification_id,
            collected_objects
        )

        # server token asset
        yield from _update_or_create_server_token_asset(
            server_token,
            server_token_asset_defaults,
            notification_id,
            collected_objects
        )

        # device assignments
        yield from _update_assignments(
            server_token, all_serial_numbers,
            notification_id,
            collected_objects
        )


def sync_asset(server_token, client, adam_id, pricing_param, notification_id):
    asset_d = client.get_asset(adam_id, pricing_param)
    if not asset_d:
        logger.error("Unknown asset %s/%s", adam_id, pricing_param)
        return
    yield from _sync_asset_d(server_token, client, asset_d, notification_id)


def sync_assets(server_token):
    client = AppsBooksClient.from_server_token(server_token)
    for asset_d in client.iter_assets():
        for event in _sync_asset_d(server_token, client, asset_d):
            event.post()
    #TODO remove server token assets not found in the batch!!!
    #make sure we are not ruining anything!!!
    #also, make sure we are not removing the assignment on something that is installed…


def _update_server_token_asset_counts(server_token_asset, updates, notification_id):
    updated = False
    for attr, count_delta in updates.items():
        if count_delta != 0:
            updated = True
        setattr(server_token_asset, attr, getattr(server_token_asset, attr) + count_delta)
    if not updated:
        return
    if server_token_asset.count_errors():
        raise ValueError
    else:
        server_token_asset.save()
        event_payload = server_token_asset.serialize_for_event(keys_only=False)
        event_payload["notification_id"] = notification_id
        yield ServerTokenAssetUpdatedEvent(
            _get_server_token_asset_event_metadata(server_token_asset),
            event_payload
        )


def update_server_token_asset_counts(server_token, client, adam_id, pricing_param, updates, notification_id):
    logger.debug("location %s asset %s/%s: update counts",
                 server_token.location_name, adam_id, pricing_param)
    with transaction.atomic():
        try:
            server_token_asset = (
                server_token.servertokenasset_set
                            .select_for_update()
                            .select_related("asset", "server_token")
                            .get(asset__adam_id=adam_id,
                                 asset__pricing_param=pricing_param)
            )
        except ServerTokenAsset.DoesNotExist:
            logger.info("location %s asset %s/%s: unknown, could not update counts, sync required",
                        server_token.location_name, adam_id, pricing_param)
        else:
            try:
                yield from _update_server_token_asset_counts(server_token_asset, updates, notification_id)
            except ValueError:
                logger.info("location %s asset %s/%s: %s, sync required",
                            server_token.location_name, adam_id, pricing_param, server_token_asset.count_errors())
            else:
                return
    yield from sync_asset(server_token, client, adam_id, pricing_param, notification_id)


def associate_server_token_asset(
    server_token, client,
    adam_id, pricing_param, serial_numbers,
    event_id, notification_id
):
    with transaction.atomic():
        try:
            server_token_asset = (
                ServerTokenAsset.objects
                                .select_for_update()
                                .select_related("asset", "server_token")
                                .get(server_token=server_token,
                                     asset__adam_id=adam_id,
                                     asset__pricing_param=pricing_param)
            )
        except ServerTokenAsset.DoesNotExist:
            logger.error("location %s asset %s/%s: unknown asset, cannot associate, sync required",
                         server_token.location_name, adam_id, pricing_param)
            yield from sync_asset(server_token, client, adam_id, pricing_param, notification_id)
        else:
            payload = server_token_asset.serialize_for_event(server_token=server_token)
            if event_id:
                payload["event_id"] = event_id
            if notification_id:
                payload["notification_id"] = notification_id
            assigned_count_delta = 0
            for serial_number in serial_numbers:
                _, created = DeviceAssignment.objects.get_or_create(
                    server_token_asset=server_token_asset,
                    serial_number=serial_number
                )
                if created:
                    assigned_count_delta += 1
                    yield DeviceAssignmentCreatedEvent(
                        EventMetadata(machine_serial_number=serial_number),
                        payload
                    )
                    # on-the-fly asset assignment done?
                    queue_install_application_command_if_necessary(
                        server_token, serial_number, adam_id, pricing_param
                    )
            try:
                yield from _update_server_token_asset_counts(
                    server_token_asset,
                    {"assigned_count": assigned_count_delta,
                     "available_count": -1 * assigned_count_delta},
                    notification_id
                )
            except ValueError:
                logger.error("location %s asset %s/%s: bad assigned count after associations, sync required",
                             server_token.location_name, adam_id, pricing_param)
                yield from sync_asset(server_token, client, adam_id, pricing_param, notification_id)


def disassociate_server_token_asset(
    server_token, client,
    adam_id, pricing_param, serial_numbers,
    event_id, notification_id
):
    with transaction.atomic():
        try:
            server_token_asset = (
                ServerTokenAsset.objects
                                .select_for_update()
                                .select_related("asset", "server_token")
                                .get(server_token=server_token,
                                     asset__adam_id=adam_id,
                                     asset__pricing_param=pricing_param)
            )
        except ServerTokenAsset.DoesNotExist:
            logger.error("location %s asset %s/%s: unknown asset, cannot disassociate, sync required",
                         server_token.location_name, adam_id, pricing_param)
            yield from sync_asset(server_token, client, adam_id, pricing_param, notification_id)
        else:
            payload = server_token_asset.serialize_for_event(server_token=server_token)
            if event_id:
                payload["event_id"] = event_id
            if notification_id:
                payload["notification_id"] = notification_id
            assigned_count_delta = 0
            for serial_number in serial_numbers:
                deleted = DeviceAssignment.objects.filter(
                    server_token_asset=server_token_asset,
                    serial_number=serial_number
                ).delete()
                if deleted:
                    assigned_count_delta -= 1
                    yield DeviceAssignmentDeletedEvent(
                        EventMetadata(machine_serial_number=serial_number),
                        payload
                    )
                # disassociated, remove the cache key if it exist for the on-the-fly assignment
                clear_on_the_fly_assignment_cache(
                    server_token, serial_number, adam_id, pricing_param, "disassociate success"
                )
            try:
                yield from _update_server_token_asset_counts(
                    server_token_asset,
                    {"assigned_count": assigned_count_delta,
                     "available_count": -1 * assigned_count_delta},
                    notification_id
                )
            except ValueError:
                logger.error("location %s asset %s/%s: bad assigned count after disassociations, sync required",
                             server_token.location_name, adam_id, pricing_param)
                yield from sync_asset(server_token, client, adam_id, pricing_param, notification_id)
