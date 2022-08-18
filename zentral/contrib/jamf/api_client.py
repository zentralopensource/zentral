import logging
from datetime import datetime, timedelta
import re
from urllib.parse import urlparse
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from dateutil import parser
from django.urls import reverse
from django.utils.functional import cached_property
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry
from zentral.conf import settings
from zentral.contrib.inventory.conf import macos_version_from_build
from zentral.contrib.inventory.utils import clean_ip_address
from zentral.utils.text import shard
from .events import JAMF_EVENTS


logger = logging.getLogger('zentral.contrib.jamf.api_client')


INVENTORY_DISPLAY_GENERAL = "General"
INVENTORY_DISPLAY_HARDWARE = "Hardware"
INVENTORY_DISPLAY_USER_AND_LOCATION = "User and Location"
INVENTORY_DISPLAY_CHOICES = (
    (INVENTORY_DISPLAY_GENERAL, INVENTORY_DISPLAY_GENERAL),
    (INVENTORY_DISPLAY_HARDWARE, INVENTORY_DISPLAY_HARDWARE),
    (INVENTORY_DISPLAY_USER_AND_LOCATION, INVENTORY_DISPLAY_USER_AND_LOCATION),
)


class CustomHTTPAdapter(HTTPAdapter):
    def __init__(self, default_timeout, max_retries):
        self.default_timeout = default_timeout
        super().__init__(
            max_retries=Retry(total=max_retries, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        )

    def send(self, *args, **kwargs):
        timeout = kwargs.get("timeout")
        if timeout is None:
            kwargs["timeout"] = self.default_timeout
        return super().send(*args, **kwargs)


class APIClientError(Exception):
    def __init__(self, message):
        self.message = message


class APIClient(object):
    default_timeout = 15  # 15 seconds
    max_retries = 3  # max 3 attempts
    # bearer token auth
    token_min_validity_seconds = 300  # 5 min

    def __init__(self, host, port, path, user, password, secret, business_unit=None, **kwargs):
        self.host, self.path, self.port, self.secret, self.business_unit = host, path, port, secret, business_unit
        self.base_url = "https://{}:{}".format(host, port)
        self.api_base_url = "{}{}".format(self.base_url, path)
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.2',
                                     'accept': 'application/json'})
        token_authentication = kwargs.get("bearer_token_authentication", False)
        if not token_authentication:
            self.token_auth = None
            self.session.auth = (user, password)
        else:
            self.token_auth = (user, password)
            self.token = None
        self.session.mount(
            self.api_base_url,
            CustomHTTPAdapter(self.default_timeout, self.max_retries)
        )
        self.mobile_device_groups = {}
        self.reverse_computer_groups = {}
        self.group_tag_regex = None
        # inventory options
        self.inventory_apps_shard = kwargs.get("inventory_apps_shard", 100)
        self.inventory_extension_attribute_set = frozenset(
            ea_name.lower()
            for ea_name in kwargs.get("inventory_extension_attributes", [])
        )
        # tags from groups
        self.tag_configs = []
        for tag_config in kwargs.get("tag_configs", []):
            tag_config = tag_config.copy()
            tag_config["regex"] = re.compile(tag_config.pop("regex"))
            self.tag_configs.append(tag_config)

    def update_token_if_necessary(self, force=False):
        if not self.token_auth:
            logger.debug("Use basic auth for %s", self.base_url)
            return
        if (
            force or
            self.token is None
            or self.token["expires"] + timedelta(seconds=self.token_min_validity_seconds) < datetime.utcnow()
        ):
            logger.info("Fetch bearer token for %s", self.base_url)
            self.session.headers.pop("Authorization", None)
            resp = self.session.post(f"{self.base_url}/api/v1/auth/token", auth=self.token_auth)
            if resp.status_code != 200:
                raise APIClientError(f"Could not get bearer token. Status code: {resp.status_code}")
            self.token = resp.json()
            self.token["expires"] = parser.parse(self.token.pop("expires"), ignoretz=True)
            logger.info("Got bearer token for %s. Expires: %s", self.base_url, self.token["expires"])
            self.session.headers["Authorization"] = f'Bearer {self.token["token"]}'
        else:
            logger.debug("Re-use bearer token for %s. Expires: %s", self.base_url, self.token["expires"])
        return self.token["token"]

    def get_source_d(self):
        return {"module": "zentral.contrib.jamf",
                "name": "jamf",
                "config": {
                    "host": self.host,
                    "path": self.path,
                    "port": self.port,
                }}

    @cached_property
    def source_repr(self):
        return "".join(s for s in (self.host,
                                   f":{self.port}" if self.port not in (80, 443, 8443) else None,
                                   self.path if self.path != "/JSSResource" else None)
                       if s)

    def _make_get_query(self, path, missing_ok=False):
        self.update_token_if_necessary()
        url = f"{self.api_base_url}{path}"
        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            raise APIClientError(f"jamf API error: {e}")
        if missing_ok and r.status_code == 404:
            return None
        elif r.status_code != requests.codes.ok:
            raise APIClientError(f"{url} jamf API HTTP response status code {r.status_code}")
        return r.json()

    def _computers(self):
        return self._make_get_query('/computers')['computers']

    def _computer(self, jamf_id):
        return self._make_get_query('/computers/id/{}'.format(jamf_id))['computer']

    def _mobile_device(self, jamf_id):
        return self._make_get_query('/mobiledevices/id/{}'.format(jamf_id))['mobile_device']

    def _machine_links_from_id(self, device_type, jamf_id):
        if device_type == "computer":
            path = "computers.html"
        elif device_type == "mobile_device":
            path = "mobileDevices.html"
        ll = []
        for anchor_text, url_tmpl in (('Inventory', "{}/{}?id={}&o=r"),
                                      ('Management', "{}/{}?id={}&o=r&v=management")):
            ll.append({'anchor_text': anchor_text,
                       'url': url_tmpl.format(self.base_url, path, jamf_id)})
        return ll

    def machine_reference(self, device_type, jamf_id):
        return "{},{}".format(device_type, jamf_id)

    def group_reference(self, device_type, group_id, is_smart):
        reference_items = [device_type]
        if is_smart:
            reference_items.append("smart")
        else:
            reference_items.append("static")
        reference_items.append(str(group_id))
        return ",".join(reference_items)

    def _group_links(self, device_type, group_id, is_smart):
        if device_type == "computer":
            path_device_type = "Computer"
        elif device_type == "mobile_device":
            path_device_type = "MobileDevice"
        if is_smart:
            path_prefix = "smart"
        else:
            path_prefix = "static"
        url_tmpl = "{}/{}{}Groups.html?id={}&o=r&nav=c"
        return [{'anchor_text': 'Group',
                 'url': url_tmpl.format(self.base_url, path_prefix, path_device_type, group_id)}]

    def rebuild_reverse_computer_groups(self):
        self.reverse_computer_groups = {
            cg["name"]: (cg["id"], cg["is_smart"])
            for cg in self._make_get_query('/computergroups')['computer_groups']
        }

    def get_computer_group(self, group_name):
        for i in range(2):
            try:
                return self.reverse_computer_groups[group_name]
            except KeyError:
                if i == 0:
                    self.rebuild_reverse_computer_groups()
                else:
                    raise

    def rebuild_mobile_device_groups(self):
        self.mobile_device_groups = {
            mdg["id"]: mdg["is_smart"]
            for mdg in self._make_get_query('/mobiledevicegroups')['mobile_device_groups']
        }

    def get_mobile_device_group_is_smart(self, group_id):
        for i in range(2):
            try:
                return self.mobile_device_groups[group_id]
            except KeyError:
                if i == 0:
                    self.rebuild_mobile_device_groups()
                else:
                    raise

    def get_group_machine_references(self, device_type, jamf_id):
        if device_type == "computer":
            path, obj_attr, list_attr = "computergroups", "computer_group", "computers"
        elif device_type == "mobile_device":
            path, obj_attr, list_attr = "mobiledevicegroups", "mobile_device_group", "mobile_devices"
        else:
            raise APIClientError(f"Unknown device type: {device_type}")
        endpoint = "/{}/id/{}".format(path, jamf_id)
        for device in self._make_get_query(endpoint)[obj_attr][list_attr]:
            yield self.machine_reference(device_type, device["id"])

    def get_machine_d(self, device_type, jamf_id):
        if device_type == "computer":
            return self.get_computer_machine_d(jamf_id)
        elif device_type == "mobile_device":
            return self.get_mobile_device_machine_d(jamf_id)
        else:
            raise APIClientError(f"Unknown device type: {device_type}")

    def get_machine_d_and_tags(self, device_type, jamf_id):
        machine_d = self.get_machine_d(device_type, jamf_id)
        tags = {}
        groups = None
        for tag_config in self.tag_configs:
            tag_names = tags.setdefault(tag_config["taxonomy_id"], [])
            if tag_config["source"] == "GROUP":
                if groups is None:
                    groups = machine_d.get("groups", [])
                for group in groups:
                    regex = tag_config["regex"]
                    group_name = group["name"]
                    if regex.match(group_name):
                        tag_name = regex.sub(tag_config["replacement"], group_name)
                        if tag_name:
                            tag_names.append(tag_name)
                        else:
                            logger.error("Empty group tag name %s %s %s", device_type, jamf_id, regex)
            else:
                logger.error("Unknown tag config source: %s", tag_config["source"])
        return machine_d, tags

    def get_computer_machine_d(self, jamf_id):
        computer = self._computer(jamf_id)
        serial_number = computer['general']['serial_number']
        # serial number, reference
        ct = {'source': self.get_source_d(),
              'reference': self.machine_reference("computer", jamf_id),
              'links': self._machine_links_from_id("computer", jamf_id),
              'serial_number': serial_number}
        last_contact = computer['general'].get('last_contact_time_utc')
        if last_contact:
            ct['last_seen'] = parser.parse(last_contact)

        # business unit
        if self.business_unit:
            ct['business_unit'] = self.business_unit
        else:
            site_id = computer['general']['site']['id']
            if site_id >= 0:
                site_reference = str(site_id)
                site_name = computer['general']['site']['name']
            else:
                site_reference = "DEFAULT"
                site_name = "Default"
            ct['business_unit'] = {'source': self.get_source_d(),
                                   'reference': site_reference,
                                   'name': site_name}

        # groups
        groups = []
        cg_names = computer['groups_accounts']['computer_group_memberships']
        org_cg_num = len(cg_names)
        cg_names = set(cg_names)
        if len(cg_names) < org_cg_num:
            logger.warning("%s computer %s: duplicated group(s)", self.api_base_url, jamf_id)
        for computer_group_name in cg_names:
            try:
                group_id, is_smart = self.get_computer_group(computer_group_name)
            except KeyError:
                logger.error("%s computer %s: could not find group '%s'",
                             self.api_base_url, jamf_id, computer_group_name)
                continue
            else:
                groups.append({'source': self.get_source_d(),
                               'reference': self.group_reference("computer", group_id, is_smart),
                               'name': computer_group_name,
                               'links': self._group_links("computer", group_id, is_smart)})
        if groups:
            ct['groups'] = groups

        hardware = computer['hardware']

        # os version
        os_version = None
        try:
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(s) for s in hardware['os_version'].split('.'))))
        except ValueError:
            try:
                os_version = macos_version_from_build(hardware["os_build"])
            except ValueError:
                pass
        else:
            os_version.update({'name': hardware['os_name'],
                               'build': hardware['os_build']})
            if 'patch' not in os_version:
                os_version['patch'] = 0
        if os_version:
            ct['os_version'] = os_version

        # system info
        system_info = {'computer_name': computer['general']['name'],
                       'hardware_model': hardware['model_identifier']}
        # cpu physical cores
        try:
            cpu_physical_cores = int(hardware['number_cores'])
        except (TypeError, ValueError):
            pass
        else:
            if cpu_physical_cores > 0:
                system_info['cpu_physical_cores'] = cpu_physical_cores
            else:
                logger.warning("%s computer %s: cpu physical cores <= 0", self.api_base_url, jamf_id)
        # physical memory
        try:
            physical_memory = int(computer['hardware']['total_ram']) * 2**20
        except (TypeError, ValueError):
            pass
        else:
            if physical_memory > 0:
                system_info['physical_memory'] = physical_memory
            else:
                logger.warning("%s computer %s physical memory <= 0 MB", self.api_base_url, jamf_id)
        # cpu type = processor_type + processor_speed_mhz
        cpu_type_items = []
        processor_type = hardware["processor_type"]
        if processor_type:
            processor_type = processor_type.strip()
            if processor_type:
                cpu_type_items.append(processor_type)
        try:
            processor_speed_mhz = int(hardware["processor_speed_mhz"])
        except (TypeError, ValueError):
            pass
        else:
            if processor_speed_mhz > 0:
                cpu_type_items.append("@{}MHZ".format(processor_speed_mhz))
            else:
                logger.warning("%s computer %s cpu speed <= 0 MHz", self.api_base_url, jamf_id)
        if cpu_type_items:
            system_info['cpu_type'] = " ".join(cpu_type_items)
        ct['system_info'] = system_info

        # public ip
        last_reported_ip = clean_ip_address(computer['general'].get('ip_address', None))
        if last_reported_ip:
            ct['public_ip_address'] = last_reported_ip

        # network interfaces
        network_interface = {}
        for attr, ni_attr in (('mac_address', 'mac'),
                              ('last_reported_ip', 'address')):
            value = computer['general'].get(attr, None)
            if value:
                if attr == "last_reported_ip":
                    value = clean_ip_address(value)
                if value:
                    network_interface[ni_attr] = value
        if len(network_interface) == 2:
            network_interface['interface'] = 'primary'
            ct['network_interfaces'] = [network_interface]

        # osx apps
        osx_app_instances = []
        if (
            self.inventory_apps_shard == 100
            or (self.inventory_apps_shard
                and serial_number
                and shard(serial_number, "jamf_apps") < self.inventory_apps_shard)
        ):
            has_duplicated_apps = False
            for app_d in computer['software']['applications']:
                osx_app_d = {'bundle_path': app_d['path'],
                             'app': {'bundle_name': app_d['name'],
                                     'bundle_version_str': app_d['version']}}
                if osx_app_d not in osx_app_instances:
                    osx_app_instances.append(osx_app_d)
                else:
                    has_duplicated_apps = True
            if has_duplicated_apps:
                logger.warning("%s computer %s: duplicated app(s)", self.api_base_url, jamf_id)
        else:
            logger.debug("%s computer %s: skipped osx app instances", self.api_base_url, jamf_id)
        ct['osx_app_instances'] = osx_app_instances

        # extension attributes → extra facts
        if self.inventory_extension_attribute_set:
            extension_attributes = computer.get("extension_attributes")
            if extension_attributes:
                extra_facts = {}
                for extention_attribute in extension_attributes:
                    extention_attribute_name = extention_attribute.get("name")
                    if not extention_attribute_name:
                        logger.warning(
                            "%s computer %s: extension attribute without name",
                            self.api_base_url, jamf_id
                        )
                        continue
                    if extention_attribute_name.lower() not in self.inventory_extension_attribute_set:
                        continue
                    value = extention_attribute.get("value")
                    if isinstance(value, list):
                        ok = len(value) < 100 and all(not isinstance(v, str) or len(v) < 1000 for v in value)
                    else:
                        ok = not isinstance(value, str) or len(value) < 1000
                    if not ok:
                        logger.error(
                            "%s computer %s ea '%s': invalid value",
                            self.api_base_url, jamf_id, extention_attribute_name
                        )
                        continue
                    extra_facts[extention_attribute_name] = value
                if extra_facts:
                    ct['extra_facts'] = extra_facts

        return ct

    def get_mobile_device_machine_d(self, jamf_id):
        mobile_device = self._mobile_device(jamf_id)
        general = mobile_device["general"]
        # serial number, reference
        mdt = {'source': self.get_source_d(),
               'reference': self.machine_reference("mobile_device", jamf_id),
               'links': self._machine_links_from_id("mobile_device", jamf_id),
               'serial_number': general['serial_number']}
        last_inventory_update = general.get('last_inventory_update_utc')
        if last_inventory_update:
            mdt['last_seen'] = parser.parse(last_inventory_update)

        # business unit
        if self.business_unit:
            mdt['business_unit'] = self.business_unit
        else:
            site_id = general['site']['id']
            if site_id >= 0:
                site_reference = str(site_id)
                site_name = general['site']['name']
            else:
                site_reference = "DEFAULT"
                site_name = "Default"
            mdt['business_unit'] = {'source': self.get_source_d(),
                                    'reference': site_reference,
                                    'name': site_name}

        # groups
        groups = []
        seen_groups = set([])
        for mobile_device_group in mobile_device['mobile_device_groups']:
            group_id = mobile_device_group["id"]
            if group_id in seen_groups:
                continue
            else:
                seen_groups.update([group_id])
            group_name = mobile_device_group["name"]
            try:
                group_is_smart = self.get_mobile_device_group_is_smart(group_id)
            except KeyError:
                # TODO
                continue
            else:
                groups.append({'source': self.get_source_d(),
                               'reference': self.group_reference("mobile_device", group_id, group_is_smart),
                               'name': group_name,
                               'links': self._group_links("mobile_device", group_id, group_is_smart)})
        if groups:
            mdt['groups'] = groups

        # os version
        try:
            os_version = dict(zip(('major', 'minor', 'patch'),
                                  (int(s) for s in general['os_version'].split('.'))))
        except ValueError:
            pass
        else:
            os_version.update({'name': general['os_type'],
                               'build': general['os_build']})
            if 'patch' not in os_version:
                os_version['patch'] = 0
            mdt['os_version'] = os_version

        # system info
        system_info = {'computer_name': general['name'],
                       'hardware_model': general['model_identifier']}
        mdt['system_info'] = system_info

        return mdt

    # policies

    def get_policy_general_info(self, jamf_id):
        general_d = self._make_get_query('/policies/id/{}'.format(jamf_id))['policy']['general']
        general_d.pop("network_limitations", None)  # TODO: any_ip_address is not an IP and triggers an elastic err
        return general_d

    # computer extension attributes

    def get_compute_extension_attribute_with_name(self, name):
        return self._make_get_query('/computerextensionattributes/name/{}'.format(name), missing_ok=True)

    def get_or_create_text_computer_extension_attribute(self, name, inventory_display):
        self.update_token_if_necessary()
        assert(inventory_display in [s for s, _ in INVENTORY_DISPLAY_CHOICES])
        cea_d = self.get_compute_extension_attribute_with_name(name)
        if cea_d:
            return cea_d["computer_extension_attribute"]["id"]
        else:
            url = '{}/computerextensionattributes/id/0'.format(self.api_base_url)
            headers = {'content-type': 'text/xml'}
            data_elm = ET.Element("computer_extension_attribute")
            name_elm = ET.SubElement(data_elm, "name")
            name_elm.text = name
            inventory_display_elm = ET.SubElement(data_elm, "inventory_display")
            inventory_display_elm.text = inventory_display
            input_type_elm = ET.SubElement(data_elm, "input_type")
            type_elm = ET.SubElement(input_type_elm, "type")
            type_elm.text = "Text Field"
            r = self.session.post(url, headers=headers, data=ET.tostring(data_elm, encoding="utf-8"))
            if r.status_code != requests.codes.created:
                raise APIClientError(r.text)
            root = ET.fromstring(r.content)
            for child in root:
                if child.tag == "id":
                    return int(child.text)
            raise APIClientError("Could not get created text computer extension attribute ID")

    def update_text_computer_extension_attribute(self, jamf_id, name, inventory_display, value):
        self.update_token_if_necessary()
        url = "{}/computers/id/{}".format(self.api_base_url, jamf_id)
        headers = {'content-type': 'text/xml'}
        cea_id = self.get_or_create_text_computer_extension_attribute(name, inventory_display)
        data_elm = ET.Element("computer")
        extension_attributes_elm = ET.SubElement(data_elm, "extension_attributes")
        attribute_elm = ET.SubElement(extension_attributes_elm, "attribute")
        id_elm = ET.SubElement(attribute_elm, "id")
        id_elm.text = str(cea_id)
        value_elm = ET.SubElement(attribute_elm, "value")
        value_elm.text = value
        r = self.session.put(url, headers=headers, data=ET.tostring(data_elm, encoding="utf-8"))
        if r.status_code != requests.codes.created:
            raise APIClientError(r.text)

    # add to or remove from group

    def get_computer_group_with_name(self, group_name):
        return self._make_get_query('/computergroups/name/{}'.format(group_name), missing_ok=True)

    def add_computer_to_group(self, jamf_id, group_name):
        self.update_token_if_necessary()
        jamf_id = int(jamf_id)
        group_d = self.get_computer_group_with_name(group_name)
        if group_d:
            for c in group_d['computer_group']['computers']:
                if c['id'] == jamf_id:
                    logger.debug("Machine {} already in group {}".format(jamf_id, group_name))
                    return
        headers = {'content-type': 'text/xml'}
        if group_d:
            jamf_group_id = group_d["computer_group"]["id"]
            url = "{}/computergroups/id/{}".format(self.api_base_url, jamf_group_id)
            data = (
                "<computer_group>"
                "<id>{}</id>"
                "<computer_additions>"
                "<computer><id>{}</id></computer>"
                "</computer_additions>"
                "</computer_group>"
            ).format(jamf_group_id, jamf_id)
            r = self.session.put(url, headers=headers, data=data)
        else:
            url = "{}/computergroups/id/0".format(self.api_base_url)
            data = (
                '<?xml version="1.0" encoding="ISO-8859-1"?>'
                "<computer_group>"
                "<name>{}</name>"
                "<is_smart>false</is_smart>"
                "<computers>"
                "<computer><id>{}</id></computer>"
                "</computers>"
                "</computer_group>"
            ).format(xml_escape(group_name), jamf_id)
            r = self.session.post(url, headers=headers, data=data.encode("iso-8859-1"))
        if r.status_code != requests.codes.created:
            raise APIClientError(r.text)

    def remove_computer_from_group(self, jamf_id, group_name):
        self.update_token_if_necessary()
        group_d = self.get_computer_group_with_name(group_name)
        if not group_d:
            logger.debug("Group %s does not exist", group_name)
            return
        else:
            jamf_group_id = group_d["computer_group"]["id"]
            jamf_id = int(jamf_id)
            for c in group_d['computer_group']['computers']:
                if c["id"] == jamf_id:
                    url = "{}/computergroups/id/{}".format(self.api_base_url, jamf_group_id)
                    headers = {'content-type': 'text/xml'}
                    data = (
                        "<computer_group>"
                        "<id>{}</id>"
                        "<computer_deletions>"
                        "<computer><id>{}</id></computer>"
                        "</computer_deletions>"
                        "</computer_group>"
                    ).format(jamf_group_id, jamf_id)
                    r = self.session.put(url, headers=headers, data=data)
                    if r.status_code != requests.codes.created:
                        raise APIClientError(f"Could not remove computer {jamf_id} from group {group_name}")
                    break
            else:
                logger.debug("Machine {} already not in group {}".format(jamf_id, group_name))

    # webhooks setup

    def _get_webhook_xml(self, event_name):
        webhook = ET.Element("webhook")
        event = ET.SubElement(webhook, "event")
        event.text = event_name
        enabled = ET.SubElement(webhook, "enabled")
        enabled.text = "false" if event_name == "RestAPIOperation" else "true"
        name = ET.SubElement(webhook, "name")
        name.text = "{} {}".format(settings["api"]["tls_hostname"], event_name)
        url = ET.SubElement(webhook, "url")
        url.text = "{}{}".format(settings["api"]["tls_hostname"],
                                 reverse("jamf:post_event", args=(self.secret,)))
        content_type = ET.SubElement(webhook, "content_type")
        content_type.text = "application/json"
        return ET.tostring(webhook)

    def _iter_instance_webhooks(self):
        for webhook in self._make_get_query('/webhooks')['webhooks']:
            webhook = self._make_get_query('/webhooks/id/{}'.format(webhook['id']))['webhook']
            o = urlparse(webhook["url"])
            if self.secret in o.path:
                yield webhook

    def setup(self):
        self.update_token_if_necessary()
        existing_webhooks = {}
        for webhook in self._iter_instance_webhooks():
            existing_webhooks[webhook['event']] = webhook['id']
        for event_name in JAMF_EVENTS:
            if event_name not in existing_webhooks:
                r = self.session.post("{}/webhooks/id/0".format(self.api_base_url),
                                      headers={'content-type': 'text/xml'},
                                      data=self._get_webhook_xml(event_name))
                if r.status_code != requests.codes.created:
                    raise APIClientError("Could not create webhook")
        return "Webhooks setup OK. {} machine(s).".format(len(self._computers()))

    def cleanup(self):
        self.update_token_if_necessary()
        for webhook in self._iter_instance_webhooks():
            self.session.delete("{}/webhooks/id/{}".format(self.api_base_url, webhook["id"]))
