import logging
import requests
from asgiref.sync import async_to_sync

from kiota_authentication_azure.azure_identity_authentication_provider import AzureIdentityAuthenticationProvider
from azure.identity.aio import ClientSecretCredential
from msgraph import GraphRequestAdapter, GraphServiceClient
from zentral.contrib.inventory.conf import windows_version_from_build


logger = logging.getLogger("zentral.contrib.intune.api_client")


class Client:
    scopes = ['https://graph.microsoft.com/.default']

    def __init__(self, business_unit, tenant_id, client_id, client_secret):
        self.business_unit = business_unit
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = requests.Session()
        # Auth conf
        self.auth_provider = AzureIdentityAuthenticationProvider(
            ClientSecretCredential(
                self.tenant_id,
                str(self.client_id),
                self.client_secret,
            ),
            scopes=self.scopes
            )
        self.request_adapter = GraphRequestAdapter(self.auth_provider)
        self.graph_client = GraphServiceClient(self.request_adapter)

    @classmethod
    def from_tenant(cls, tenant):
        ''' Setting un credentials and the Graph API Client'''
        client = cls(
            tenant.business_unit,
            tenant.tenant_id,
            tenant.client_id,
            tenant.get_client_secret(),
        )
        return client

    def iter_machine_snapshot_trees(self):
        # TODO: Use batches for processing
        # https://learn.microsoft.com/en-us/graph/query-parameters?tabs=http
        results = []

        @async_to_sync
        async def consume_data():
            async for device in self.iter_devices():
                results.append(device)
        consume_data()

        # FIXME: get a batch of devices to avoid a big results array
        for device in results:
            try:
                yield self.build_machine_snapshot_tree(device)
            except Exception:
                logger.exception("Device %s: could not build machine snapshot tree", device.id)

    async def iter_devices(self):
        ''' TODO:
            - Use device_batch_size to retrieve results
            - Order by device id, and use the "top" query parameter,
              and device id > last seen device id if possible.
            - How to sort the call and paginate
        '''
        resp = await self.graph_client.device_management.managed_devices.get()
        for managed_device in resp.value:
            yield managed_device

    def build_machine_snapshot_tree(self, device):
        ''' TODO:
            - add to the tree apps (another API call)
            - add groups
        '''

        device_id = device.id
        serial_number = device.serial_number
        if not serial_number:
            raise ValueError(f"Device {device.id}: no serial number")
        ms_tree = {
            "source": self.get_source_d(),
            "reference": device_id,
            "links": [{"anchor_text": "Device details",
                       "url": (
                            "https://endpoint.microsoft.com/#view/Microsoft_Intune_Devices"
                            "/DeviceSettingsMenuBlade/~/overview/mdmDeviceId/"
                            f"{device_id}/primaryUserId/"
                       )}],
            "serial_number": serial_number,
            "imei": device.imei,
            "business_unit": self.get_business_unit_d(),
            "system_info": {
                "computer_name": device.device_name,
                "hardware_model": device.model,
            }
        }
        ms_tree["last_seen"] = device.last_sync_date_time

        self.add_ms_tree_extra_facts(ms_tree, device)
        self.add_ms_tree_os_version(ms_tree, device)
        self.add_ms_tree_disk(ms_tree, device)
        self.add_ms_tree_network_interfaces(ms_tree, device)
        self.add_ms_tree_principal_user(ms_tree, device)
        return ms_tree

    # helper methods

    def get_business_unit_d(self):
        return self.business_unit.serialize()

    def get_source_d(self):
        return {
            "module": "zentral.contrib.intune",
            "name": "Intune",
            "config": {
                "tenant_id": self.tenant_id
            }
        }

    def add_ms_tree_extra_facts(self, ms_tree, device):
        extra_facts = {}
        compliance_status = device.compliance_state
        if isinstance(compliance_status, str):
            extra_facts["compliance_status"] = compliance_status
        extra_facts["partner_reported_threat_state"] = self.translate_partner_reported_threat_state(device)
        extra_facts["azure_ad_device_id"] = device.azure_a_d_device_id
        if extra_facts:
            ms_tree["extra_facts"] = extra_facts

    def translate_partner_reported_threat_state(self, device):
        match device.partner_reported_threat_state:
            case 0:
                return "Unknown"
            case 1:
                return "Activated"
            case 2:
                return "Deactivated"
            case 3:
                return "Secured"
            case 4:
                return "Low Severity"
            case 5:
                return "Medium Severity"
            case 6:
                return "High Severity"
            case 7:
                return "Unresponsive"
            case 8:
                return "Compromised"
            case 9:
                return "Misconfigured"
        return None

    def add_ms_tree_os_version(self, ms_tree, device):
        operating_system = device.operating_system.lower()
        if operating_system == "windows":
            os_build = ".".join(device.os_version.split('.')[-2:])
            try:
                os_version_d = windows_version_from_build(os_build)
            except ValueError:
                logging.exception("Device %s: could not parse OS version", device.id)
                return
        elif operating_system in ("ios", "ipados", "macos", "tvos"):
            try:
                version, build = device.os_version.split()
                build = build.strip("()")
                os_version_tuple = tuple(int(s) for s in version.split('.'))
                os_version_d = dict(zip(('major', 'minor', 'patch'), os_version_tuple))
            except (ValueError, AttributeError):
                logger.exception("Device %s: could not parse OS version", device.id)
                return
            os_version_d["name"] = device.operating_system
            if build:
                os_version_d["build"] = build
        else:
            raise ValueError(f"Unknown Operating System: {operating_system}")

        if os_version_d.get("major"):
            ms_tree["os_version"] = os_version_d

    def add_ms_tree_disk(self, ms_tree, device):
        device_capacity = device.total_storage_space_in_bytes
        if device_capacity > 0:
            ms_tree["disks"] = [{"name": "root", "size": device_capacity}]

    def add_ms_tree_network_interfaces(self, ms_tree, device):
        network_interfaces = ms_tree.setdefault("network_interfaces", [])
        mac = device.ethernet_mac_address
        if mac:
            network_interfaces.append({"interface": "ethernet", "mac": mac})
        mac = device.wi_fi_mac_address
        if mac:
            network_interfaces.append({"interface": "wifi", "mac": mac})

    def add_ms_tree_principal_user(self, ms_tree, device):
        user_principal_name = device.user_principal_name
        user_id = device.user_id
        user_display_name = device.user_display_name
        if user_principal_name and user_id:
            ms_tree["principal_user"] = {
                "source": {"type": "INVENTORY",
                           "properties": self.get_source_d()},
                "unique_id": user_id,
                "principal_name": user_principal_name,
                "display_name": user_display_name
            }
