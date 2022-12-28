from datetime import datetime
import logging
from zentral.contrib.mdm.inventory import commit_update_tree, tree_from_payload
from zentral.contrib.mdm.models import Channel, Platform
from zentral.utils.json import prepare_loaded_plist
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.device_information")


class DeviceInformation(Command):
    request_type = "DeviceInformation"
    reschedule_notnow = True

    # https://developer.apple.com/documentation/devicemanagement/deviceinformationcommand/command/queries
    queries = [
        "AccessibilitySettings",  # iOS >= 16
        "ActiveManagedUsers",  # macOS >= 10.11
        "AppAnalyticsEnabled",  # iOS >= 4, macOS >= 10.7
        "AutoSetupAdminAccounts",  # macOS >= 10.11
        "AvailableDeviceCapacity",  # iOS >= 4, macOS >= 10.7
        "AwaitingConfiguration",
        "BatteryLevel",  # iOS >= 5
        "BluetoothMAC",
        "BuildVersion",
        "CellularTechnology",  # iOS >= 4.2.6
        "DataRoamingEnabled",  # iOS >= 5
        "DeviceCapacity",  # iOS >= 4, macOS >= 10.7
        "DeviceID",  # tvOS >= 6
        "DeviceName",
        "DevicePropertiesAttestation",  # iOS >= 16, tvOS >= 16
        "DiagnosticSubmissionEnabled",  # iOS >= 9.3
        "EASDeviceIdentifier",  # iOS >= 7
        "EstimatedResidentUsers",  # Shared iPad, iOS >= 14
        "EthernetMAC",  # macOS >= 10.7
        "HostName",  # macOS >= 10.11
        "IsActivationLockSupported",  # macOS >= 10.9
        "IsAppleSilicon",  # macOS >= 10.12
        "IsCloudBackupEnabled",  # iOS >= 7.1
        "IsDeviceLocatorServiceEnabled",  # iOS >= 7
        "IsDoNotDisturbInEffect",  # iOS >= 7
        "IsMDMLostModeEnabled",  # iOS >= 9.3
        "IsMultiUser",  # iOS >= 9.3
        "IsNetworkTethered",  # iOS >= 10.3
        "IsRoaming",  # iOS >= 4.2
        "IsSupervised",  # iOS >= 6, macOS >= 10.15, tvOS >= 9
        "iTunesStoreAccountHash",
        "iTunesStoreAccountIsActive",
        "LastCloudBackupDate",  # iOS >= 8
        "LocalHostName",  # macOS >= 10.11
        "ManagedAppleIDDefaultDomains",  # Shared iPad, iOS >= 16
        "MaximumResidentUsers",  # Shared iPad, iOS >= 9.3
        "MDMOptions",
        "Model",
        "ModelName",
        "ModemFirmwareVersion",  # iOS >= 4
        "OnlineAuthenticationGracePeriod",  # Shared iPad, iOS >= 16
        "OrganizationInfo",
        "OSUpdateSettings",
        "OSVersion",
        "PersonalHotspotEnabled",
        "PINRequiredForDeviceLock",  # macOS >= 11
        "PINRequiredForEraseDevice",  # macOS >= 11
        "ProductName",
        "ProvisioningUDID",  # macOS >= 11.3
        # "PushToken",  User channel only iOS >= 9.3, macOS >= 10.12
        "QuotaSize",  # Shared iPad, iOS >= 13.4
        "ResidentUsers",  # Shared iPad, iOS >= 13.4
        "SerialNumber",
        "ServiceSubscriptions",
        "SoftwareUpdateDeviceID",  # iOS >= 15, macOS >= 12
        "SupportsiOSAppInstalls",  # macOS >= 11
        "SupportsLOMDevice",  # macOS >= 11
        "SystemIntegrityProtectionEnabled",  # macOS >= 10.12
        "TemporarySessionOnly",
        "TemporarySessionTimeout",
        "TimeZone",  # iOS >= 14, tvOS >= 14
        "UDID",
        "UserSessionTimeout",
        "WiFiMAC",
    ]

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            (
                channel == Channel.Device
                or enrolled_device.platform in (Platform.macOS.name, Platform.iPadOS.name)
            ) and (
                not enrolled_device.user_enrollment
                or enrolled_device.platform in (Platform.iOS.name, Platform.macOS.name)
            )
        )

    def build_command(self):
        return {"Queries": self.queries}

    def command_acknowledged(self):
        query_responses = self.response.get("QueryResponses")
        if not query_responses:
            logger.warning("Enrolled device %s: absent or empty QueryResponses in DeviceInformation response.",
                           self.enrolled_device.serial_number)
            return
        # inventory tree
        ms_tree = tree_from_payload(self.enrolled_device.udid,
                                    self.enrolled_device.serial_number,
                                    self.meta_business_unit,
                                    query_responses)
        commit_update_tree(self.enrolled_device, ms_tree, missing_ok=True)
        # enrolled device
        self.enrolled_device.device_information = prepare_loaded_plist(query_responses)
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        # platform
        try:
            platform = ms_tree["os_version"]["name"]
        except KeyError:
            logger.error("Enrolled device %s: could not get platform.", self.enrolled_device.serial_number)
        else:
            if platform and self.enrolled_device.platform != platform:
                logger.warning("Enrolled device %s: platform change.", self.enrolled_device.serial_number)
                self.enrolled_device.platform = platform
        # Awaiting configuration
        self.enrolled_device.awaiting_configuration = query_responses.get("AwaitingConfiguration")
        # OS version
        os_version = query_responses.get("OSVersion")
        if os_version:
            self.enrolled_device.os_version = os_version
        # Apple silicon
        apple_silicon = query_responses.get("IsAppleSilicon")
        if apple_silicon is not None:
            self.enrolled_device.apple_silicon = apple_silicon
        # supervised
        supervised = query_responses.get("IsSupervised")
        if supervised is not None:
            self.enrolled_device.supervised = supervised
        # save enrolled device
        self.enrolled_device.save()


register_command(DeviceInformation)
