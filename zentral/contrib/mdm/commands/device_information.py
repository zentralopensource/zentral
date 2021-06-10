import logging
from zentral.contrib.mdm.inventory import commit_tree_from_payload
from zentral.contrib.mdm.models import Channel, Platform
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.device_information")


class DeviceInformation(Command):
    request_type = "DeviceInformation"
    allowed_channel = (Channel.Device, Channel.User)
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True

    # https://developer.apple.com/documentation/devicemanagement/deviceinformationcommand/command/queries
    queries = [
        "ActiveManagedUsers",
        "AppAnalyticsEnabled",
        "AutoSetupAdminAccounts",
        "AvailableDeviceCapacity",
        "AwaitingConfiguration",
        "BatteryLevel",
        "BluetoothMAC",
        "BuildVersion",
        "CarrierSettingsVersion",
        "CellularTechnology",
        "CurrentCarrierNetwork",
        "CurrentMCC",
        "CurrentMNC",
        "DataRoamingEnabled",
        "DeviceCapacity",
        "DeviceID",
        "DeviceName",
        "DiagnosticSubmissionEnabled",
        "EASDeviceIdentifier",
        "EstimatedResidentUsers",
        "EthernetMAC",
        "EthernetMACs",
        "HostName",
        "ICCID",
        "IMEI",
        "IsActivationLockEnabled",
        "IsActivationLockSupported",
        "IsAppleSilicon",
        "IsCloudBackupEnabled",
        "IsDeviceLocatorServiceEnabled",
        "IsDoNotDisturbInEffect",
        "IsMDMLostModeEnabled",
        "IsMultiUser",
        "IsNetworkTethered",
        "IsRoaming",
        "IsSupervised",
        "iTunesStoreAccountHash",
        "iTunesStoreAccountIsActive"
        "LastCloudBackupDate",
        "LocalHostName",
        "MaximumResidentUsers",
        "MDMOptions",
        "MEID",
        "Model",
        "ModelName",
        "ModemFirmwareVersion",
        "OrganizationInfo",
        "OSUpdateSettings",
        "OSVersion",
        "PersonalHotspotEnabled",
        "PhoneNumber",
        "PINRequiredForDeviceLock",
        "PINRequiredForEraseDevice",
        "ProductName",
        "ProvisioningUDID",
        "PushToken",
        "QuotaSize",
        "ResidentUsers",
        "SerialNumber",
        "ServiceSubscriptions",
        "SoftwareUpdateDeviceID",
        "SubscriberCarrierNetwork",
        "SubscriberMCC",
        "SubscriberMNC",
        "SupportsiOSAppInstalls",
        "SupportsLOMDevice",
        "SystemIntegrityProtectionEnabled",
        "TemporarySessionOnly",
        "TemporarySessionTimeout",
        "TimeZone",
        "UDID",
        "UserSessionTimeout",
        "VoiceRoamingEnabled",
        "WiFiMAC",
    ]

    def build_command(self):
        return {"Queries": self.queries}

    def command_acknowledged(self):
        query_responses = self.response.get("QueryResponses")
        if query_responses:
            commit_tree_from_payload(self.enrolled_device.udid,
                                     self.enrolled_device.serial_number,
                                     self.meta_business_unit,
                                     query_responses)
        else:
            logger.warning("Enrolled device %s: absent or empty QueryResponses in DeviceInformation response.",
                           self.enrolled_device.udid)


register_command(DeviceInformation)
