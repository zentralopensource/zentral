import logging
from zentral.contrib.mdm.models import Channel, Platform
from zentral.contrib.mdm.inventory import ms_tree_from_payload, update_inventory_tree
from zentral.utils.json import prepare_loaded_plist
from .base import register_command, Command, CommandBaseForm


logger = logging.getLogger("zentral.contrib.mdm.commands.device_information")


class DeviceInformationForm(CommandBaseForm):
    pass


class DeviceInformation(Command):
    request_type = "DeviceInformation"
    display_name = "Device information"
    reschedule_notnow = True
    store_result = True
    form_class = DeviceInformationForm

    # https://developer.apple.com/documentation/devicemanagement/deviceinformationcommand/command/queries
    # Last check 2022-12-29
    # Access rights:
    #   16: Device information
    #   32: Network information
    # 4096: App management
    # Some keys are not documented!
    queries = (
        # Device information queries key, Access Rights, Platforms
        ("AccessibilitySettings", None, {"iOS": (16,)}),
        ("ActiveManagedUsers", 16, {"macOS": (10, 11)}),
        ("AppAnalyticsEnabled", 16, {"iOS": (4,), "macOS": (10, 7)}),
        ("AutoSetupAdminAccounts", 16, {"macOS": (10, 11)}),
        ("AvailableDeviceCapacity", 16, {"iOS": (4,), "macOS": (10, 7)}),
        ("AwaitingConfiguration", None, None),
        ("BatteryLevel", 16, {"iOS": (4,)}),
        ("BluetoothMAC", 32, {"iOS": (5,)}),
        ("BuildVersion", 16, None),
        ("CellularTechnology", 16, {"iOS": (4, 2, 6)}),
        ("DataRoamingEnabled", 32, {"iOS": (5,)}),
        ("DeviceCapacity", 16, {"iOS": (4,), "macOS": (10, 7)}),
        ("DeviceID", 16, {"tvOS": (6,)}),
        ("DeviceName", 16, None),
        ("DevicePropertiesAttestation", None, {"iOS": (16,), "tvOS": (16,)}),
        ("DiagnosticSubmissionEnabled",  16, {"iOS": (9, 3)}),
        ("EASDeviceIdentifier", 16, {"iOS": (7,)}),
        ("EstimatedResidentUsers", 16, {"iOS": (14,)}),  # Shared iPad
        ("EthernetMAC", 32, {"macOS": (10, 7)}),
        ("HostName", None, {"macOS": (10, 11)}),
        ("IsActivationLockSupported", None, {"macOS": (10, 9)}),
        ("IsAppleSilicon", None, {"macOS": (12,)}),
        ("IsCloudBackupEnabled", 16, {"iOS": (7, 1)}),
        ("IsDeviceLocatorServiceEnabled", 16, {"iOS": (7,)}),
        ("IsDoNotDisturbInEffect", 16, {"iOS": (7,)}),
        ("IsMDMLostModeEnabled", 16, {"iOS": (9, 3)}),
        ("IsMultiUser", 16, {"iOS": (9, 3)}),
        ("IsNetworkTethered", 32, {"iOS": (10, 3)}),
        ("IsRoaming", 32, {"iOS": (4, 2)}),
        ("IsSupervised", 16, {"iOS": (6,), "macOS": (10, 15), "tvOS": (9,)}),
        ("iTunesStoreAccountHash", 4096, None),
        ("iTunesStoreAccountIsActive", 4096, None),
        ("LastCloudBackupDate", None, {"iOS": (8,)}),
        ("LocalHostName", None, {"macOS": (10, 11)}),
        ("ManagedAppleIDDefaultDomains", None, {"iOS": (16,)}),  # Shared iPad
        # MaximumResidentUsers always returns 32 since iOS 13.4
        ("MDMOptions", None, None),
        ("Model", 16, None),
        ("ModelName", 16, None),
        ("ModemFirmwareVersion", 16, {"iOS": (4,)}),
        ("OnlineAuthenticationGracePeriod", None, {"iOS": (16,)}),  # Shared iPad
        ("OrganizationInfo", None, None),
        ("OSUpdateSettings", 16, {"macOS": (10, 11)}),
        ("OSVersion", 16, None),
        ("PersonalHotspotEnabled", 32, {"iOS": (7,)}),
        ("PINRequiredForDeviceLock", None, {"macOS": (11,)}),
        ("PINRequiredForEraseDevice", None, {"macOS": (11,)}),
        ("ProductName", 16, None),
        ("ProvisioningUDID", None, {"macOS": (11, 3)}),
        # PushToken User channel only iOS >= 9.3, macOS >= 10.12
        ("QuotaSize", 16, {"iOS": (13, 4)}),  # Shared iPad
        ("ResidentUsers", 16, {"iOS": (13, 4)}),  # Shared iPad
        ("SerialNumber", 16, None),
        ("ServiceSubscriptions", 32, None),
        ("SkipLanguageAndLocaleSetupForNewUsers", None, None),  # Not documented
        ("SoftwareUpdateDeviceID", None, {"iOS": (15,), "macOS": (12,)}),
        ("SoftwareUpdateSettings", None, None),  # Not documented
        ("SupplementalBuildVersion", None, None),  # Not documented
        ("SupplementalOSVersionExtra", None, None),  # Not documented
        ("SupportsiOSAppInstalls", None, {"macOS": (11,)}),
        ("SupportsLOMDevice", None, {"macOS": (11,)}),
        ("SystemIntegrityProtectionEnabled", 16, {"macOS": (10, 12)}),
        ("TemporarySessionOnly", None, None),
        ("TemporarySessionTimeout", None, None),
        ("TimeZone", 16, {"iOS": (14,), "tvOS": (14,)}),
        ("UDID", None, None),
        ("UserSessionTimeout", None, None),
        ("WiFiMAC", 32, None),
    )

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
        return {"Queries": [k for k, _, _ in self.queries]}

    def get_inventory_partial_tree(self):
        payload = self.response["QueryResponses"]
        return ms_tree_from_payload(payload)

    def command_acknowledged(self):
        query_responses = self.response.get("QueryResponses")
        if not query_responses:
            logger.error("Enrolled device %s: absent or empty QueryResponses in DeviceInformation response.",
                         self.enrolled_device.serial_number)
            return
        # inventory tree
        ms_tree = update_inventory_tree(self, commit_enrolled_device=False)
        # enrolled device
        self.enrolled_device.device_information = prepare_loaded_plist(query_responses)
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
        # OS version extra
        os_version_extra = query_responses.get("SupplementalOSVersionExtra")
        if os_version_extra:
            self.enrolled_device.os_version_extra = os_version_extra
        # Build version
        build_version = query_responses.get("BuildVersion")
        if build_version:
            self.enrolled_device.build_version = build_version
        # Build version extra
        build_version_extra = query_responses.get("SupplementalBuildVersion")
        if build_version_extra:
            self.enrolled_device.build_version_extra = build_version_extra
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
