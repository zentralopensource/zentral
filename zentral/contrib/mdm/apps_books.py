from datetime import datetime, timedelta
from itertools import islice
import logging
import threading
from django.db import transaction
from django.db.models import F
from django.urls import reverse
from django.utils.functional import SimpleLazyObject
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from urllib.parse import urljoin
from base.utils import deployment_info
from zentral.conf import settings
from zentral.core.events.base import EventMetadata
from .artifacts import Target
from .commands.install_application import InstallApplication
from .events import (AssetCreatedEvent, AssetUpdatedEvent,
                     DeviceAssignmentCreatedEvent, DeviceAssignmentDeletedEvent,
                     LocationAssetCreatedEvent, LocationAssetUpdatedEvent)
from .incidents import MDMAssetAvailabilityIncident
from .models import (Asset, Artifact, DeviceAssignment,
                     EnrolledDeviceLocationAssetAssociation,
                     Location, LocationAsset)


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


class AppsBooksAPIError(Exception):
    pass


class MDMConflictError(Exception):
    pass


class FetchedDataUpdatedError(Exception):
    pass


class AppsBooksClient:
    base_url = "https://vpp.itunes.apple.com/mdm/v2/"
    timeout = 5
    retries = 2

    def __init__(
        self,
        server_token=None,
        mdm_info_id=None,
        location_name=None,
        platform=None,
        location=None
    ):
        self.server_token = server_token
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": deployment_info.user_agent,
            "Authorization": "Bearer " + server_token
        })
        adapter = CustomHTTPAdapter(self.timeout, self.retries)
        self.session.mount("https://", adapter)
        self.mdm_info_id = mdm_info_id
        self.location_name = location_name
        self.platform = platform or "enterprisestore"
        self._service_config = None
        self.location = location

    @classmethod
    def from_location(cls, location):
        return cls(location.get_server_token(),
                   str(location.mdm_info_id),
                   location.name,
                   location.platform,
                   location)

    def close(self):
        self.session.close()

    def make_request(self, path, retry_if_invalid_token=True, verify_mdm_info=False, **kwargs):
        url = urljoin(self.base_url, path)
        if "json" in kwargs:
            method = self.session.post
        else:
            method = self.session.get
        resp = method(url, **kwargs)
        resp.raise_for_status()
        response = resp.json()
        errorNumber = response.get("errorNumber")
        if errorNumber:
            if errorNumber == 9622 and retry_if_invalid_token:
                if not self.location:
                    raise AppsBooksAPIError("Invalid server token")
                logger.debug("Location %s: refresh session token", self.location_name)
                self.location.refresh_from_db()
                self.server_token = self.location.get_server_token()
                self.session.headers["Authorization"] = "Bearer " + self.server_token
                return self.make_request(path, False, verify_mdm_info, **kwargs)
            else:
                logger.error("Location %s: API error %s %s",
                             self.location_name, errorNumber, response.get("errorMessage", "-"))
                raise AppsBooksAPIError(f"Error {errorNumber}")
        if (
            verify_mdm_info
            and self.mdm_info_id is not None
            and response.get("mdmInfo", {}).get("id") != self.mdm_info_id
        ):
            msg = f"Location {self.location_name}: mdmInfo mismatch"
            logger.error(msg)
            raise MDMConflictError(msg)
        return response

    # client config

    def get_client_config(self):
        return self.make_request("client/config", verify_mdm_info=True)

    def update_client_config(self, notification_auth_token):
        assert self.mdm_info_id is not None and notification_auth_token is not None
        return self.make_request(
            "client/config",
            json={
                "mdmInfo": {
                    "id": self.mdm_info_id,
                    "metadata": settings["api"]["fqdn"],
                    "name": "Zentral"
                },
                "notificationTypes": ["ASSET_MANAGEMENT", "ASSET_COUNT"],
                "notificationUrl": "https://{}{}".format(
                    settings["api"]["webhook_fqdn"],
                    reverse("mdm:notify_location", args=(self.mdm_info_id,))
                ),
                "notificationAuthToken": notification_auth_token,
            }
        )

    # service config

    def get_service_config(self):
        if not self._service_config:
            self._service_config = self.make_request("service/config")
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
        try:
            resp = requests.get(
                url,
                params={"version": 2,
                        "p": "mdm-lockup",  # TODO: Really?
                        "caller": "MDM",
                        "platform": self.platform,
                        "cc": "us",
                        "l": "en",
                        "id": adam_id},
                cookies={"itvt": self.server_token}
            )
            resp.raise_for_status()
        except Exception:
            logger.exception("Location %s: could not get asset %s metadata.", self.location_name, adam_id)
        else:
            return resp.json().get("results", {}).get(adam_id)

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


# location cache


class LocationCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._locations = {}

    def get(self, mdm_info_id):
        if not isinstance(mdm_info_id, str):
            mdm_info_id = str(mdm_info_id)
        with self._lock:
            try:
                return self._locations[mdm_info_id]
            except KeyError:
                location = None
                client = None
                try:
                    location = Location.objects.get(mdm_info_id=mdm_info_id)
                except Location.DoesNotExist:
                    raise KeyError
                else:
                    client = AppsBooksClient.from_location(location)
                self._locations[mdm_info_id] = location, client
                return location, client


location_cache = SimpleLazyObject(lambda: LocationCache())


#
# on-the-fly assignment
#
# Instead of sending the InstallApplication command directly a device asset
# association is triggered and an EnrolledDeviceLocationAssetAssociation object is
# created. When the assignment notification is received, the
# EnrolledDeviceLocationAssetAssociation is retrieved to check if there is an artifact
# version to install.  The EnrolledDeviceLocationAssetAssociation object is also used
# to avoid triggering the association too often.
#


def ensure_enrolled_device_location_asset_association(enrolled_device, location_asset):
    serial_number = enrolled_device.serial_number
    if DeviceAssignment.objects.filter(
        serial_number=serial_number,
        location_asset=location_asset,
    ).count():
        return True
    with transaction.atomic():
        edlaa, created = EnrolledDeviceLocationAssetAssociation.objects.select_for_update().get_or_create(
            enrolled_device=enrolled_device,
            location_asset=location_asset
        )
        if created or (datetime.utcnow() - edlaa.last_attempted_at) > timedelta(minutes=30):  # TODO hardcoded, verify
            location = location_asset.location
            asset = location_asset.asset
            _, client = location_cache.get(location.mdm_info_id)
            ok = False
            try:
                response = client.post_device_association(serial_number, asset)
            except Exception:
                logger.exception("enrolled device %s asset %s/%s/%s: could not post association",
                                 serial_number, location.name, asset.adam_id, asset.pricing_param)
            else:
                event_id = response.get("eventId")
                if event_id:
                    ok = True
            if not ok:
                edlaa.delete()
            else:
                edlaa.attempts = F("attempts") + 1
                edlaa.last_attempted_at = datetime.utcnow()
                edlaa.save()
    return False


def queue_install_application_command_if_necessary(location, serial_number, adam_id, pricing_param):
    with transaction.atomic():
        try:
            edlaa = EnrolledDeviceLocationAssetAssociation.objects.select_for_update().select_related(
                "enrolled_device",
                "location_asset__asset",
            ).get(
                enrolled_device__serial_number=serial_number,
                location_asset__location=location,
                location_asset__asset__adam_id=adam_id,
                location_asset__asset__pricing_param=pricing_param
            )
        except EnrolledDeviceLocationAssetAssociation.DoesNotExist:
            logger.error("enrolled device %s asset %s/%s/%s: no awaiting association found",
                         serial_number, location.name, adam_id, pricing_param)
        else:
            target = Target(edlaa.enrolled_device)
            # find the latest artifact version to install for this asset
            for artifact_version in target.all_to_install(included_types=(Artifact.Type.STORE_APP,)):
                if artifact_version.store_app.location_asset == edlaa.location_asset:
                    InstallApplication.create_for_target(target, artifact_version, queue=True)
                    break
            else:
                logger.error("enrolled device %s asset %s/%s/%s: no artifact version to install found",
                             serial_number, location.name, adam_id, pricing_param)
            # cleanup
            edlaa.delete()


def clear_on_the_fly_assignment(location, serial_number, adam_id, pricing_param, reason):
    count, _ = EnrolledDeviceLocationAssetAssociation.objects.filter(
        enrolled_device__serial_number=serial_number,
        location_asset__location=location,
        location_asset__asset__adam_id=adam_id,
        location_asset__asset__pricing_param=pricing_param
    ).delete()
    if count:
        logger.error("enrolled device %s asset %s/%s/%s: on-the-fly assignment canceled, %s",
                     serial_number, location.name, adam_id, pricing_param, reason)


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


def _get_location_asset_event_metadata(location_asset):
    incident_updates = []
    incident_update_severity = location_asset.get_availability_incident_severity()
    if incident_update_severity is not None:
        incident_updates.append(
            MDMAssetAvailabilityIncident.build_incident_update(
                location_asset, incident_update_severity
            )
        )
    return EventMetadata(incident_updates=incident_updates)


def _update_or_create_location_asset(location, defaults, notification_id, collected_objects):
    asset = collected_objects["asset"]
    location_asset, created = LocationAsset.objects.select_for_update().get_or_create(
        location=location,
        asset=asset,
        defaults=defaults
    )
    collected_objects["location_asset"] = location_asset
    if created:
        payload = location_asset.serialize_for_event(
            keys_only=False, location=location, asset=asset
        )
        if notification_id:
            payload["notification_id"] = notification_id
        yield LocationAssetCreatedEvent(
            _get_location_asset_event_metadata(location_asset),
            payload
        )
    else:
        updated = False
        for attr, new_val in defaults.items():
            old_val = getattr(location_asset, attr)
            if old_val != new_val:
                setattr(location_asset, attr, new_val)
                updated = True
        if updated:
            location_asset.save()
            payload = location_asset.serialize_for_event(
                    keys_only=False, location=location, asset=asset
            )
            if notification_id:
                payload["notification_id"] = notification_id
            yield LocationAssetUpdatedEvent(
                _get_location_asset_event_metadata(location_asset),
                payload
            )


def _update_assignments(location, all_serial_numbers, notification_id, collected_objects):
    asset = collected_objects["asset"]
    location_asset = collected_objects["location_asset"]
    existing_serial_numbers = set(location_asset.deviceassignment_set.values_list("serial_number", flat=True))
    if all_serial_numbers == existing_serial_numbers:
        return

    # prepare common event payload
    payload = location_asset.serialize_for_event(keys_only=False, location=location, asset=asset)
    if notification_id:
        payload["notification_id"] = notification_id

    # prune assignments
    removed_serial_numbers = existing_serial_numbers - all_serial_numbers
    if removed_serial_numbers:
        DeviceAssignment.objects.filter(location_asset=location_asset,
                                        serial_number__in=removed_serial_numbers).delete()
        for serial_number in removed_serial_numbers:
            yield DeviceAssignmentDeletedEvent(EventMetadata(machine_serial_number=serial_number), payload)

    # add missing assignments
    added_serial_numbers = all_serial_numbers - existing_serial_numbers
    if not added_serial_numbers:
        return
    batch_size = 1000  # TODO: hard-coded
    assignments_to_create = (DeviceAssignment(location_asset=location_asset,
                                              serial_number=serial_number)
                             for serial_number in added_serial_numbers)
    while True:
        batch = list(islice(assignments_to_create, batch_size))
        if not batch:
            break
        DeviceAssignment.objects.bulk_create(batch, batch_size)
    for serial_number in added_serial_numbers:
        yield DeviceAssignmentCreatedEvent(EventMetadata(machine_serial_number=serial_number), payload)


def _sync_asset_d(location, client, asset_d, notification_id=None):
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

    location_asset_defaults = {
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

        # location asset
        yield from _update_or_create_location_asset(
            location,
            location_asset_defaults,
            notification_id,
            collected_objects
        )

        # device assignments
        yield from _update_assignments(
            location, all_serial_numbers,
            notification_id,
            collected_objects
        )


def sync_asset(location, client, adam_id, pricing_param, notification_id):
    asset_d = client.get_asset(adam_id, pricing_param)
    if not asset_d:
        logger.error("Unknown asset %s/%s", adam_id, pricing_param)
        return
    yield from _sync_asset_d(location, client, asset_d, notification_id)


def sync_assets(location):
    client = AppsBooksClient.from_location(location)
    for asset_d in client.iter_assets():
        for event in _sync_asset_d(location, client, asset_d):
            event.post()


def _update_location_asset_counts(location_asset, updates, notification_id):
    updated = False
    for attr, count_delta in updates.items():
        if count_delta != 0:
            updated = True
        setattr(location_asset, attr, getattr(location_asset, attr) + count_delta)
    if not updated:
        return
    if location_asset.count_errors():
        raise ValueError
    else:
        location_asset.save()
        event_payload = location_asset.serialize_for_event(keys_only=False)
        event_payload["notification_id"] = notification_id
        yield LocationAssetUpdatedEvent(
            _get_location_asset_event_metadata(location_asset),
            event_payload
        )


def update_location_asset_counts(location, client, adam_id, pricing_param, updates, notification_id):
    logger.debug("location %s asset %s/%s: update counts",
                 location.name, adam_id, pricing_param)
    with transaction.atomic():
        try:
            location_asset = (
                location.locationasset_set
                        .select_for_update()
                        .select_related("asset", "location")
                        .get(asset__adam_id=adam_id,
                             asset__pricing_param=pricing_param)
            )
        except LocationAsset.DoesNotExist:
            logger.info("location %s asset %s/%s: unknown, could not update counts, sync required",
                        location.name, adam_id, pricing_param)
        else:
            try:
                yield from _update_location_asset_counts(location_asset, updates, notification_id)
            except ValueError:
                logger.info("location %s asset %s/%s: %s, sync required",
                            location.name, adam_id, pricing_param,
                            ", ".join(location_asset.count_errors()))
            else:
                return
    yield from sync_asset(location, client, adam_id, pricing_param, notification_id)


def associate_location_asset(
    location, client,
    adam_id, pricing_param, serial_numbers,
    event_id, notification_id
):
    with transaction.atomic():
        try:
            location_asset = (
                LocationAsset.objects.select_for_update()
                                     .select_related("asset", "location")
                                     .get(location=location,
                                          asset__adam_id=adam_id,
                                          asset__pricing_param=pricing_param)
            )
        except LocationAsset.DoesNotExist:
            logger.error("location %s asset %s/%s: unknown asset, cannot associate, sync required",
                         location.name, adam_id, pricing_param)
            yield from sync_asset(location, client, adam_id, pricing_param, notification_id)
        else:
            payload = location_asset.serialize_for_event(location=location)
            if event_id:
                payload["event_id"] = event_id
            if notification_id:
                payload["notification_id"] = notification_id
            assigned_count_delta = 0
            for serial_number in serial_numbers:
                _, created = DeviceAssignment.objects.get_or_create(
                    location_asset=location_asset,
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
                        location, serial_number, adam_id, pricing_param
                    )
            try:
                yield from _update_location_asset_counts(
                    location_asset,
                    {"assigned_count": assigned_count_delta,
                     "available_count": -1 * assigned_count_delta},
                    notification_id
                )
            except ValueError:
                logger.error("location %s asset %s/%s: bad assigned count after associations, sync required",
                             location.name, adam_id, pricing_param)
                yield from sync_asset(location, client, adam_id, pricing_param, notification_id)


def disassociate_location_asset(
    location, client,
    adam_id, pricing_param, serial_numbers,
    event_id, notification_id
):
    with transaction.atomic():
        try:
            location_asset = (
                LocationAsset.objects.select_for_update()
                                     .select_related("asset", "location")
                                     .get(location=location,
                                          asset__adam_id=adam_id,
                                          asset__pricing_param=pricing_param)
            )
        except LocationAsset.DoesNotExist:
            logger.error("location %s asset %s/%s: unknown asset, cannot disassociate, sync required",
                         location.name, adam_id, pricing_param)
            yield from sync_asset(location, client, adam_id, pricing_param, notification_id)
        else:
            payload = location_asset.serialize_for_event(location=location)
            if event_id:
                payload["event_id"] = event_id
            if notification_id:
                payload["notification_id"] = notification_id
            assigned_count_delta = 0
            for serial_number in serial_numbers:
                deleted = DeviceAssignment.objects.filter(
                    location_asset=location_asset,
                    serial_number=serial_number
                ).delete()
                if deleted:
                    assigned_count_delta -= 1
                    yield DeviceAssignmentDeletedEvent(
                        EventMetadata(machine_serial_number=serial_number),
                        payload
                    )
                # disassociated, remove the on-the-fly assignment if it exists
                clear_on_the_fly_assignment(
                    location, serial_number, adam_id, pricing_param, "disassociate success"
                )
            try:
                yield from _update_location_asset_counts(
                    location_asset,
                    {"assigned_count": assigned_count_delta,
                     "available_count": -1 * assigned_count_delta},
                    notification_id
                )
            except ValueError:
                logger.error("location %s asset %s/%s: bad assigned count after disassociations, sync required",
                             location.name, adam_id, pricing_param)
                yield from sync_asset(location, client, adam_id, pricing_param, notification_id)
