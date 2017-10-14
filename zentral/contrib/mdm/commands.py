import plistlib
import uuid
from django.http import HttpResponse


def build_command_response(request_type, content, command_uuid=None):
    if command_uuid is None:
        command_uuid = str(uuid.uuid4())
    content["RequestType"] = request_type
    command = {"CommandUUID": command_uuid,
               "Command": content}
    return HttpResponse(plistlib.dumps(command),
                        content_type="application/xml; charset=UTF-8")


DEVICE_INFORMATION_QUERIES = [
    # General
    "UDID",
    "Languages",
    "Locales",
    "DeviceID",
    "OrganizationInfo",
    "LastCloudBackupDate",
    "AwaitingConfiguration",
    "AutoSetupAdminAccounts",

    # iTunes - Needs Install Applications access right
    "iTunesStoreAccountIsActive",
    "iTunesStoreAccountHash",

    # Device Information
    "DeviceName",
    "OSVersion",
    "BuildVersion",
    "ModelName",
    "Model",
    "ProductName",
    "SerialNumber",
    "DeviceCapacity",
    "AvailableDeviceCapacity",
    "BatteryLevel",
    "CellularTechnology",
    "IMEI",
    "MEID",
    "ModemFirmwareVersion",
    "IsSupervised",
    "IsDeviceLocatorServiceEnabled",
    "IsActivationLockEnabled",
    "IsDoNotDisturbInEffect",
    "DeviceID",
    "EASDeviceIdentifier",
    "IsCloudBackupEnabled",
    "OSUpdateSettings",
    "LocalHostName",
    "HostName",
    "SystemIntegrityProtectionEnabled",
    "ActiveManagedUsers",
    "IsMDMLostModeEnabled",
    "MaximumResidentUsers",

    # OS update
    "CatalogURL",
    "IsDefaultCatalog",
    "PreviousScanDate",
    "PreviousScanResult",
    "PerformPeriodicCheck",
    "AutomaticCheckEnabled",
    "BackgroundDownloadEnabled",
    "AutomaticAppInstallationEnabled",
    "AutomaticOSInstallationEnabled",
    "AutomaticSecurityUpdatesEnabled"
]


def build_device_information_command_response():
    return build_command_response("DeviceInformation", {"Queries": DEVICE_INFORMATION_QUERIES})
