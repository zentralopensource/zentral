import logging
from dateutil import parser
from urllib.parse import urlparse
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape as xml_escape
from django.urls import reverse
import requests
from requests.packages.urllib3.util import Retry
from zentral.conf import settings
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


class APIClientError(Exception):
    def __init__(self, message):
        self.message = message


class APIClient(object):
    def __init__(self, host, port, path, user, password, secret, business_unit=None, **kwargs):
        self.host, self.path, self.port, self.secret, self.business_unit = host, path, port, secret, business_unit
        self.base_url = "https://{}:{}".format(host, port)
        self.api_base_url = "{}{}".format(self.base_url, path)
        # requests session setup
        self.session = requests.Session()
        self.session.headers.update({'user-agent': 'zentral/0.0.1',
                                     'accept': 'application/json'})
        self.session.auth = (user, password)
        max_retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        self.session.mount(self.api_base_url,
                           requests.adapters.HTTPAdapter(max_retries=max_retries))
        self.mobile_device_groups = {}
        self.reverse_computer_groups = {}

    def get_source_d(self):
        return {"module": "zentral.contrib.jamf",
                "name": "jamf",
                "config": {
                    "host": self.host,
                    "path": self.path,
                    "port": self.port,
                }}

    def get_webhook_url(self):
        return "{}{}".format(settings["api"]["tls_hostname"],
                             reverse("jamf:post_event", args=(self.secret,)))

    def get_webhook_name(self, event):
        return "{} {}".format(settings["api"]["tls_hostname"], event)

    def _make_get_query(self, path, missing_ok=False):
        url = "%s%s" % (self.api_base_url, path)
        try:
            r = self.session.get(url)
        except requests.exceptions.RequestException as e:
            raise APIClientError("jamf API error: {}".format(str(e)))
        if missing_ok and r.status_code == 404:
            return None
        elif r.status_code != requests.codes.ok:
            raise APIClientError("{} jamf API HTTP response status code {}".format(url, r.status_code))
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
            raise APIClientError("Unknown device type {}".format(device_type))
        endpoint = "/{}/id/{}".format(path, jamf_id)
        for device in self._make_get_query(endpoint)[obj_attr][list_attr]:
            yield self.machine_reference(device_type, device["id"])

    def get_machine_d(self, device_type, jamf_id):
        if device_type == "computer":
            return self.get_computer_machine_d(jamf_id)
        elif device_type == "mobile_device":
            return self.get_mobile_device_machine_d(jamf_id)
        else:
            raise APIClientError("Unknown device type %s", device_type)

    def get_computer_machine_d(self, jamf_id):
        computer = self._computer(jamf_id)
        # serial number, reference
        ct = {'source': self.get_source_d(),
              'reference': self.machine_reference("computer", jamf_id),
              'links': self._machine_links_from_id("computer", jamf_id),
              'serial_number': computer['general']['serial_number']}
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
            logger.warning('Dupplicated group. source %s, machine %s',
                           self.get_source_d(), jamf_id)
        for computer_group_name in cg_names:
            try:
                group_id, is_smart = self.get_computer_group(computer_group_name)
            except KeyError:
                # TODO
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
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in hardware['os_version'].split('.'))))
        os_version.update({'name': hardware['os_name'],
                           'build': hardware['os_build']})
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
        last_reported_ip = computer['general'].get('ip_address', None)
        if last_reported_ip:
            ct['public_ip_address'] = last_reported_ip

        # network interfaces
        network_interface = {}
        for attr, ni_attr in (('mac_address', 'mac'),
                              ('last_reported_ip', 'address')):
            value = computer['general'].get(attr, None)
            if value:
                network_interface[ni_attr] = value
        if len(network_interface) == 2:
            network_interface['interface'] = 'primary'
            ct['network_interfaces'] = [network_interface]

        # osx apps
        osx_app_instances = []
        for app_d in computer['software']['applications']:
            osx_app_instances.append({'bundle_path': app_d['path'],
                                      'app': {'bundle_name': app_d['name'],
                                              'bundle_version_str': app_d['version']}})
        ct['osx_app_instances'] = osx_app_instances
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
        os_version = dict(zip(('major', 'minor', 'patch'),
                              (int(s) for s in general['os_version'].split('.'))))
        os_version.update({'name': general['os_type'],
                           'build': general['os_build']})
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
        group_d = self.get_computer_group_with_name(group_name)
        if not group_d:
            logger.debug("Group {} does not exist".format(group_name))
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
                        raise APIClientError()
                    break
            else:
                logger.debug("Machine {} already not in group {}".format(jamf_id, group_name))

    # webhooks setup

    def iter_instance_webhooks(self):
        for webhook in self._make_get_query('/webhooks')['webhooks']:
            webhook = self._make_get_query('/webhooks/id/{}'.format(webhook['id']))['webhook']
            o = urlparse(webhook["url"])
            if self.secret in o.path:
                yield webhook

    def setup(self):
        existing_webhooks = {}
        for webhook in self.iter_instance_webhooks():
            existing_webhooks[webhook['event']] = webhook['id']
        for event in JAMF_EVENTS:
            if event not in existing_webhooks:
                data = (
                    "<webhook>"
                    "<name>{name}</name>"
                    "<enabled>true</enabled>"
                    "<url>{url}</url>"
                    "<content_type>application/json</content_type>"
                    "<event>{event}</event>"
                    "</webhook>"
                ).format(name=xml_escape(self.get_webhook_name(event)),
                         url=xml_escape(self.get_webhook_url()),
                         event=xml_escape(event))
                r = self.session.post("{}/webhooks/id/0".format(self.api_base_url),
                                      headers={'content-type': 'text/xml'},
                                      data=data)
                if r.status_code != requests.codes.created:
                    raise APIClientError("Could not create webhook")
        return "Webhooks setup OK. {} machine(s).".format(len(self._computers()))

    def cleanup(self):
        for webhook in self.iter_instance_webhooks():
            self.session.delete("{}/webhooks/id/{}".format(self.api_base_url, webhook["id"]))
