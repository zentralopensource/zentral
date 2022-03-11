from collections import defaultdict
from datetime import datetime
from enum import Enum
import logging
import os.path
import time
from urllib.parse import urljoin, urlparse
import uuid
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from requests.packages.urllib3.util.ssl_ import create_urllib3_context
from base.utils import deployment_info


logger = logging.getLogger("zentral.contrib.wsone.api_client")


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, default_timeout):
        self.default_timeout = default_timeout
        self.ssl_context = create_urllib3_context(ciphers="ECDHE+AESGCM:!ECDSA")  # avoid DH_KEY_TOO_SMALL error
        super().__init__(
            max_retries=Retry(total=4, backoff_factor=2, status_forcelist=[500, 502, 503, 504])
        )

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().proxy_manager_for(*args, **kwargs)

    def send(self, *args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(*args, **kwargs)


class TooManyRequestsError(Exception):
    pass


class ClientAuth(Enum):
    BASIC = 1
    OAUTH = 2


class Client:
    token_min_validity_seconds = 300
    paginate_by = 500
    default_timeout = 15  # seconds

    def __init__(self, business_unit, server_url, api_key, excluded_groups=None):
        self.business_unit = business_unit
        self.server_url = server_url
        self.host = urlparse(self.server_url).netloc  # used in preprocessor
        self.excluded_groups = frozenset(excluded_groups or [])
        self.session = requests.Session()
        self.session.headers.update({
            "user-agent": deployment_info.user_agent,
            "aw-tenant-code": api_key
        })
        self.session.mount(server_url, CustomHTTPAdapter(self.default_timeout))
        self.auth = None
        self._profiles = {}  # profile cache
        self._groups = None  # groups cache
        self._reverse_groups = None  # groups cache
        self._groups_fetched_at = None  # groups cache
        self.latest_rate_limit = None

    def configure_oauth(self, client_id, client_secret, token_url):
        self.auth = ClientAuth.OAUTH
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.token = None
        self.token_fetched_at = None

    def configure_basic_auth(self, user, password):
        self.auth = ClientAuth.BASIC
        self.session.auth = (user, password)

    @classmethod
    def from_instance(cls, instance):
        client = cls(
            instance.business_unit,
            instance.server_url,
            instance.get_api_key(),
            instance.excluded_groups
        )
        client.configure_oauth(
            instance.client_id,
            instance.get_client_secret(),
            instance.token_url
        )
        return client

    def update_access_token(self, force=False):
        if not self.auth == ClientAuth.OAUTH:
            return
        if (
            force or
            self.token is None or
            self.token_fetched_at + self.token["expires_in"] - self.token_min_validity_seconds < time.monotonic()
        ):
            resp = requests.post(
                self.token_url,
                data={"client_id": self.client_id,
                      "client_secret": self.client_secret,
                      "grant_type": "client_credentials"}
            )
            resp.raise_for_status()
            self.token = resp.json()
            self.token["expires_in"] = int(self.token.pop("expires_in"))
            self.token_fetched_at = time.monotonic()
            self.session.headers["Authorization"] = f'Bearer {self.token["access_token"]}'
        return self.token["access_token"]

    def make_request(self, path, version=1, ignore_status_code=None, **params):
        if self.auth == ClientAuth.OAUTH:
            self.update_access_token()
        resp = self.session.get(
            urljoin(self.server_url, os.path.join("/api", path)),
            params={k: v for k, v in params.items() if v is not None},
            headers={"Accept": f"application/json;version={version}"},
        )
        try:
            self.latest_rate_limit = {
                "limit": int(resp.headers.get("X-RateLimit-Limit")),
                "remaining": int(resp.headers.get("X-RateLimit-Remaining")),
                "reset": datetime.utcfromtimestamp(int(resp.headers.get("X-RateLimit-Reset"))),
            }
        except Exception:
            logger.exception("Could not get rate limit info")
        if ignore_status_code and resp.status_code == ignore_status_code:
            return None
        if resp.status_code == 429:
            logger.error(
                "Status code 429: %s",
                ", ".join(f"{k}: {v}" for k, v in self.latest_rate_limit.items()) if self.latest_rate_limit else "???"
            )
            raise TooManyRequestsError
        resp.raise_for_status()
        if not resp.content:
            # return empty object if response is empty!
            return {}
        return resp.json()

    def is_excluded_event(self, event):
        self.build_groups_cache()
        if not event or not self.excluded_groups:
            return False
        group_name = event.get("OrganizationGroupName")
        if not group_name:
            return False
        group_ids = self._reverse_groups.get(group_name)
        if group_ids is None:
            return False
        if all(self.excluded_groups.isdisjoint(self.group_and_parents_names(group_id))
               for group_id in group_ids):
            return False
        return True

    def is_excluded_device(self, device):
        if not device or not self.excluded_groups:
            return False
        group_id = device.get("LocationGroupId", {}).get("Id", {}).get("Value")
        if not group_id:
            return False
        if self.excluded_groups.isdisjoint(self.group_and_parents_names(group_id)):
            return False
        return True

    def iter_devices(self, location_group_id=None):
        page = 0
        seen_serial_numbers = set([])
        while True:
            resp = self.make_request(
                "mdm/devices/search",
                pagesize=self.paginate_by,
                page=page,
                orderby="deviceid",
                sortorder="DESC",
                lgid=location_group_id
            )
            for device in resp["Devices"]:
                if self.is_excluded_device(device):
                    continue
                serial_number = device.get("SerialNumber") or device.get("Udid")
                if serial_number:
                    if serial_number in seen_serial_numbers:
                        continue
                    else:
                        seen_serial_numbers.add(serial_number)
                yield device
            if (page + 1) * self.paginate_by >= resp["Total"]:
                break
            page += 1

    def get_device(self, device_id):
        try:
            uuid.UUID(device_id)
        except (AttributeError, ValueError):
            version = 1
        else:
            version = 4
        device = self.make_request(f"mdm/devices/{device_id}", version=version, ignore_status_code=404)
        if device and not self.is_excluded_device(device):
            return device

    def iter_device_apps(self, device_uuid):
        page = 0
        while True:
            resp = self.make_request(f"mdm/devices/{device_uuid}/apps/search", pagesize=self.paginate_by, page=page)
            for app in resp["app_items"]:
                yield app
            if (page + 1) * self.paginate_by >= resp["TotalResults"]:
                break
            page += 1

    def iter_device_profiles(self, device_id):
        page = 0
        while True:
            resp = self.make_request(f"mdm/devices/{device_id}/profiles", pagesize=self.paginate_by, page=page)
            for profile in resp.get("DeviceProfiles", []):  # sometimes the response is empty!
                yield profile
            if (page + 1) * self.paginate_by >= resp.get("Total", 0):  # sometimes the response is empty!
                break
            page += 1

    def get_profile(self, profile_id, force=False):
        try:
            profile, fetched_at = self._profiles[profile_id]
        except KeyError:
            from_cache = False
        else:
            from_cache = time.monotonic() - fetched_at < 120  # 2 min
        if not from_cache:
            profile = self.make_request(
                f"mdm/profiles/{profile_id}",
                version=2, ignore_status_code=400
            )
            self._profiles[profile_id] = (profile, time.monotonic())
        return profile

    def iter_apps(self):
        page = 0
        while True:
            resp = self.make_request("mam/apps/search", pagesize=self.paginate_by, page=page, version=4)
            for application in resp["applications"]:
                yield application
            if (page + 1) * self.paginate_by >= resp["total"]:
                break
            page += 1

    def iter_app_devices(self, app_uuid):
        page = 0
        while True:
            resp = self.make_request(f"mam/apps/{app_uuid}/devices", pagesize=self.paginate_by, page=page)
            for device in resp["devices"]:
                if device["installed_status"] != "Installed":
                    continue
                yield (device["device_uuid"], device["installed_version"])
            if (page + 1) * self.paginate_by >= resp["TotalResults"]:
                break
            page += 1

    def iter_groups(self):
        page = 0
        while True:
            resp = self.make_request("system/groups/search", pagesize=self.paginate_by, page=page, version=2)
            for group in resp["OrganizationGroups"]:
                yield group
            if (page + 1) * self.paginate_by >= resp["TotalResults"]:
                break
            page += 1

    def iter_group_children(self, group_id):
        for child in self.make_request(f"system/groups/{group_id}/children"):
            if child["Id"]["Value"] == group_id:
                continue
            yield child

    def build_groups_cache(self, force=False):
        if (
            self._groups is None or self._reverse_groups is None
            or force
            or (self._groups_fetched_at and time.monotonic() - self._groups_fetched_at > 120)  # 2 min
        ):
            groups = {}
            reverse_groups = defaultdict(set)
            for group in self.iter_groups():
                group_id = group["Id"]
                group_name = group["Name"]
                reverse_groups[group_name].add(group_id)
                if group_id in groups:
                    continue
                groups[group_id] = {"name": group_name,
                                    "parent": None}
                for child in self.iter_group_children(group_id):
                    child_id = child["Id"]["Value"]
                    child_name = child["Name"]
                    reverse_groups[child_name].add(child_id)
                    parent_id = child.get("ParentLocationGroup", {}).get("Id", {}).get("Value")
                    if child_id in groups:
                        groups[child_id]["parent"] = parent_id
                    else:
                        groups[child_id] = {"name": child_name,
                                            "parent": parent_id}
            self._groups_fetched_at = time.monotonic()
            self._groups = groups
            self._reverse_groups = reverse_groups

    def group_and_parents_names(self, group_id):
        self.build_groups_cache()
        names = []
        while group_id:
            try:
                group_d = self._groups[group_id]
            except KeyError:
                logger.warning("Unknown group %s", group_id)
                break
            else:
                names.append(group_d["name"])
                group_id = group_d["parent"]
        return names

    # inventory methods

    def get_business_unit_d(self):
        return self.business_unit.serialize()

    def get_source_d(self):
        return {
            "module": "zentral.contrib.wsone",
            "name": "Workspace ONE",
            "config": {
                "host": self.host
            }
        }

    def add_ms_tree_extra_facts(self, ms_tree, device_d):
        extra_facts = {}
        compliance_status = device_d.get("ComplianceStatus")
        if isinstance(compliance_status, str):
            extra_facts["compliance_status"] = compliance_status
        compromised_status = device_d.get("CompromisedStatus")
        if isinstance(compromised_status, bool):
            extra_facts["compromised_status"] = compromised_status
        if extra_facts:
            ms_tree["extra_facts"] = extra_facts

    def add_ms_tree_os_version(self, ms_tree, device_d):
        try:
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(s) for s in device_d["OperatingSystem"].split('.'))))
        except (TypeError, ValueError):
            logger.warning("Device %s: could not parse OS version", device_d.get("Uuid", "?"))
            return
        device_model = device_d["Model"]
        device_platform = device_d["Platform"]
        os_version_t = tuple(os_version.get(k) for k in ("major", "minor", "patch"))
        if device_platform == "Apple":
            os_name = "iOS"
            if "ipad" in device_model.lower() and os_version_t >= (13, 1):
                os_name = "iPadOS"
        elif device_platform == "AppleOsX":
            os_name = "macOS"
            if os_version_t < (10, 12):
                os_name = "OS X"
        elif device_platform == "WinRT":
            if os_version_t < (10,):
                os_name = "Windows"
            elif os_version_t < (10, 0, 22000):
                os_name = "Windows 10"
            else:
                os_name = "Windows 11"
        elif device_platform == "Android":
            os_name = "Android"
        else:
            raise ValueError(f"Unknown platform {device_platform}")
        os_version["name"] = os_name
        os_version["build"] = device_d.get("OSBuildVersion")
        ms_tree["os_version"] = os_version

    def add_ms_tree_disk(self, ms_tree, device_d):
        device_uuid = device_d["Uuid"]
        try:
            device_capacity = int(device_d["DeviceCapacity"])
        except KeyError:
            logger.debug("Device %s: missing device capacity", device_uuid)
        except (TypeError, ValueError):
            logger.debug("Device %s: could not parse device capacity", device_uuid)
        else:
            if device_capacity > 0:
                ms_tree["disks"] = [{"name": "root", "size": device_capacity}]

    def add_ms_tree_network_interfaces(self, ms_tree, device_d):
        for network_info in device_d.get("DeviceNetworkInfo", []):
            interface = network_info.get("ConnectionType")
            mac = network_info.get("MACAddress")
            if not interface or not mac:
                continue
            network_interface = {"interface": interface, "mac": mac}
            network_interfaces = ms_tree.setdefault("network_interfaces", [])
            if network_interface not in network_interfaces:
                network_interfaces.append(network_interface)

    def add_ms_tree_principal_user(self, ms_tree, device_d):
        user_email = device_d.get("UserEmailAddress")
        user_uuid = device_d.get("UserId", {}).get("Uuid")
        user_name = device_d.get("UserId", {}).get("Name")
        if user_email and user_uuid:
            ms_tree["principal_user"] = {
                "source": {"type": "INVENTORY",
                           "properties": self.get_source_d()},
                "unique_id": user_uuid,
                "principal_name": user_email,
                "display_name": user_name
            }

    def add_ms_tree_apps(self, ms_tree, device_d):
        device_platform = device_d["Platform"]
        device_uuid = device_d["Uuid"]
        for app in self.iter_device_apps(device_d["Uuid"]):
            if app["installed_status"] != "Installed":
                continue
            app_name = app["name"]
            if not app_name:
                logger.warning("Device %s: app without name", device_uuid)
                continue
            app_version = app["installed_version"]
            if not app_version:
                logger.warning("Device %s: app without installed version", device_uuid)
                continue
            if device_platform == "Apple":
                ios_app = {"name": app_name, "version": app_version}
                ios_apps = ms_tree.setdefault("ios_apps", [])
                if ios_app not in ios_apps:
                    ios_apps.append(ios_app)
            elif device_platform == "AppleOsX":
                osx_app_instance = {"app": {"bundle_name": app_name, "bundle_version_str": app_version}}
                osx_app_instances = ms_tree.setdefault("osx_app_instances", [])
                if osx_app_instance not in osx_app_instances:
                    osx_app_instances.append(osx_app_instance)
            elif device_platform == "Android":
                android_app = {"display_name": app_name, "version_name": app_version}
                android_apps = ms_tree.setdefault("android_apps", [])
                if android_app not in android_apps:
                    android_apps.append(android_app)
            elif device_platform == "WinRT":
                program_instance = {"program": {"name": app_name, "version": app_version}}
                program_instances = ms_tree.setdefault("program_instances", [])
                if program_instance not in program_instances:
                    program_instances.append(program_instance)
            else:
                raise ValueError(f"Device {device_uuid}: unknown platform {device_platform}")

    def add_ms_tree_profiles(self, ms_tree, device_d):
        device_platform = device_d["Platform"]
        if device_platform not in ("Apple", "AppleOsX"):
            # Unsupported in the Inventory models at time of implementation
            return
        for profile_status in self.iter_device_profiles(int(device_d["Id"]["Value"])):
            if profile_status["InstalledProfileVersion"] < profile_status["CurrentVersion"]:
                continue
            profile_id = profile_status["Id"]["Value"]
            detailed_profile = self.get_profile(profile_id)
            if not detailed_profile:
                continue
            profile_g = detailed_profile["General"]
            profile = {"uuid": profile_g["ProfileUuid"],
                       "display_name": profile_g["Name"],
                       "verified": profile_g["IsManaged"],
                       "removal_disallowed": profile_g["AllowRemoval"] != "Always"}
            if profile_g["Description"]:
                profile["description"] = profile_g["Description"]
            profiles = ms_tree.setdefault("profiles", [])
            if profile not in profiles:
                profiles.append(profile)

    def build_machine_snapshot_tree(self, device_d):
        device_id = int(device_d["Id"]["Value"])
        device_uuid = device_d["Uuid"]
        serial_number = device_d.get("SerialNumber") or device_d.get("Udid")
        if not serial_number:
            raise ValueError(f"Device {device_uuid}: no serial number")
        ms_tree = {
            "source": self.get_source_d(),
            "reference": device_uuid,
            "links": [{"anchor_text": "Device details",
                       "url": f"{self.server_url}/AirWatch/#/AirWatch/Device/Details/Summary/{device_id}"}],
            "serial_number": serial_number,
            "business_unit": self.get_business_unit_d(),
            "groups": [{"source": self.get_source_d(),
                        "reference": device_d["LocationGroupId"]["Uuid"],
                        "name": device_d["LocationGroupId"]["Name"]}],
            "system_info": {
                "computer_name": device_d["DeviceFriendlyName"],
                "hardware_model": device_d["Model"],
            }
        }
        try:
            ms_tree["last_seen"] = datetime.fromisoformat(device_d["LastSeen"])
        except (KeyError, TypeError, ValueError):
            logger.warning("Device %s: could not parse last seen timestamp", device_uuid)

        self.add_ms_tree_extra_facts(ms_tree, device_d)
        self.add_ms_tree_os_version(ms_tree, device_d)
        self.add_ms_tree_disk(ms_tree, device_d)
        self.add_ms_tree_network_interfaces(ms_tree, device_d)
        self.add_ms_tree_principal_user(ms_tree, device_d)
        self.add_ms_tree_apps(ms_tree, device_d)
        self.add_ms_tree_profiles(ms_tree, device_d)

        return ms_tree

    def get_machine_snapshot_tree(self, device_id):
        device = self.get_device(device_id)
        if not device:
            return
        try:
            return self.build_machine_snapshot_tree(device)
        except Exception:
            logger.exception("Device %s: could not build machine snapshot tree", device_id)

    def iter_machine_snapshot_trees(self):
        for device in self.iter_devices():
            try:
                yield self.build_machine_snapshot_tree(device)
            except Exception:
                logger.exception("Device %s: could not build machine snapshot tree", device.get("Uuid") or "?")
