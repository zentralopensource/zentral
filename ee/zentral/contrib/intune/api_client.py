import logging
from asgiref.sync import async_to_sync
from azure.identity.aio import ClientSecretCredential
from kiota_authentication_azure.azure_identity_authentication_provider import AzureIdentityAuthenticationProvider
from msgraph import GraphRequestAdapter, GraphServiceClient
from msgraph.generated.device_management.managed_devices.managed_devices_request_builder import (
    ManagedDevicesRequestBuilder
)
from msgraph_core import GraphClientFactory
from zentral.contrib.inventory.conf import windows_version_from_build
import httpx

logger = logging.getLogger("zentral.contrib.intune.api_client")


class Client:
    paginate_by = 500

    def __init__(self, business_unit, tenant_id, client_id, client_secret):
        self.business_unit = business_unit
        self.tenant_id = tenant_id
        # Auth conf
        self.auth_provider = AzureIdentityAuthenticationProvider(
            ClientSecretCredential(
                tenant_id,
                str(client_id),
                client_secret,
            )
        )

    def graph_service_client_factory(self):
        # We need to build a client with a new httpx.AsyncClient() every time we use async_to_sync
        # to avoid the RuntimeError('Event loop is closed')
        http_client = GraphClientFactory.create_with_default_middleware(client=httpx.AsyncClient())
        request_adapter = GraphRequestAdapter(self.auth_provider, http_client)
        return GraphServiceClient(request_adapter=request_adapter)

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
        page_number = 0
        while True:
            results = self.get_devices(page_number)

            if not results:
                break
            for device in results:
                try:
                    yield self.build_machine_snapshot_tree(device)
                except Exception:
                    logger.exception("Device %s: could not build machine snapshot tree", device.id)
            page_number += 1

    @async_to_sync
    async def get_devices(self, page_number):
        offset = page_number * self.paginate_by
        query_params_kwargs = {
            "top": offset + self.paginate_by,
            "orderby": "id",
        }
        if offset:
            query_params_kwargs["skip"] = offset

        query_params = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters(
            **query_params_kwargs
        )
        request_config = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetRequestConfiguration(
            query_parameters=query_params
        )

        client = self.graph_service_client_factory()
        resp = await client.device_management.managed_devices.get(request_configuration=request_config)
        return resp.value

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

    @staticmethod
    def _get_enum_value(value):
        # because automatically generated MS Enums seem to be tupes,
        # we need to unpack them…
        # See for example: https://github.com/microsoftgraph/msgraph-sdk-python/blob/5f98ebefef9c4a30b59c5942f794df2a3cead1e5/msgraph/generated/models/managed_device_owner_type.py#L3  # NOQA
        value = value.value
        if isinstance(value, tuple):
            value = value[0]
        return value

    def add_ms_tree_extra_facts(self, ms_tree, device):
        ms_tree["extra_facts"] = {
            "compliance_state": self._get_enum_value(device.compliance_state),
            "managed_device_owner_type": self._get_enum_value(device.managed_device_owner_type),
            "partner_reported_threat_state": self._get_enum_value(device.partner_reported_threat_state),
        }
        if device.azure_a_d_device_id:
            ms_tree["extra_facts"]["azure_ad_device_id"] = device.azure_a_d_device_id

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
