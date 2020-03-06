import base64
import copy
import plistlib
import uuid
from django.http import HttpResponse
from django.urls import reverse
from django.utils import timezone
from zentral.conf import settings
from .models import DeviceCommand
from .payloads import build_payload, build_profile, get_payload_identifier


def build_device_command(enrolled_device, request_type, body_command, command_uuid=None, queue=False):
    device_command = DeviceCommand(enrolled_device=enrolled_device,
                                   request_type=request_type)

    body_command["RequestType"] = request_type
    body = {"Command": body_command}

    if command_uuid:
        device_command.uuid = command_uuid
    else:
        device_command.uuid = uuid.uuid4()
    body["CommandUUID"] = str(device_command.uuid)

    device_command.body = plistlib.dumps(body).decode("utf-8")

    if not queue:
        device_command.time = timezone.now()

    device_command.save()
    return device_command


def build_device_command_response(device_command):
    return HttpResponse(device_command.body.encode("utf-8"),
                        content_type="application/xml; charset=UTF-8")


def build_device_configured_command(enrolled_device):
    return build_device_command(enrolled_device, "DeviceConfigured", {})


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


def build_device_information_command(enrolled_device):
    return build_device_command(enrolled_device, "DeviceInformation", {"Queries": DEVICE_INFORMATION_QUERIES})


def build_install_profile_command(enrolled_device, artifact):
    artifact_suffix = artifact.get_configuration_profile_payload_identifier_suffix()
    payloads = []
    for idx, (payload_type, payload_name, payload_content) in enumerate(artifact.get_payloads()):
        payloads.append(build_payload(payload_type, payload_name,
                                      "{}.{}".format(artifact_suffix, idx + 1), payload_content,
                                      payload_version=artifact.version))
    command_payload = build_profile(str(artifact), artifact_suffix, payloads)
    return build_device_command(enrolled_device, "InstallProfile", {"Payload": command_payload})


def build_remove_profile_command(enrolled_device, artifact):
    artifact_suffix = artifact.get_configuration_profile_payload_identifier_suffix()
    identifier = get_payload_identifier(artifact_suffix)
    return build_device_command(enrolled_device, "RemoveProfile", {"Identifier": identifier})


def build_install_application_command(enrolled_device):
    command_uuid = uuid.uuid4()
    manifest_url = "{}{}".format(settings["api"]["tls_hostname"],
                                 reverse("mdm:install_application_manifest", args=(str(command_uuid),)))
    return build_device_command(enrolled_device,
                                "InstallApplication",
                                {"ManifestURL": manifest_url,
                                 # Remove app when MDM profile is removed:
                                 # TODO: make it configurable ?
                                 "ManagementFlags": 1},
                                command_uuid)


def serialize_realm_user_password_hash(realm_user):
    password_hash = realm_user.password_hash
    if not password_hash:
        return
    password_hash = copy.deepcopy(password_hash)
    for hash_type, hash_dict in password_hash.items():
        for k, v in hash_dict.items():
            if isinstance(v, str):
                # decode base64 encoded bytes
                hash_dict[k] = base64.b64decode(v.encode("utf-8"))  # => bytes to get <data/> in the plist
    return plistlib.dumps(password_hash).strip()


def queue_account_configuration_command_if_needed(enrolled_device, dep_profile, realm_user):
    payload = {"DontAutoPopulatePrimaryAccountInfo": True,
               "AutoSetupAdminAccounts": []}
    # auto setup admin accounts…
    # TODO

    # auto populate primary account
    if dep_profile.use_realm_user and dep_profile.realm_user_is_admin:
        serialized_password_hash = serialize_realm_user_password_hash(realm_user)
        if not serialized_password_hash:
            # Auto populate
            payload["DontAutoPopulatePrimaryAccountInfo"] = False
            payload["PrimaryAccountFullName"] = realm_user.get_full_name()
            payload["PrimaryAccountUserName"] = realm_user.get_device_username()
            payload["SetPrimarySetupAccountAsRegularUser"] = False
        else:
            # Auto setup admin
            admin_account = {"fullName": realm_user.get_full_name(),
                             "shortName": realm_user.get_device_username(),
                             "hidden": False,  # TODO => DEP Profile
                             "passwordHash": serialized_password_hash}
            payload["AutoSetupAdminAccounts"].append(admin_account)

    auto_populate = payload.get("DontAutoPopulatePrimaryAccountInfo") is False
    auto_setup = len(payload["AutoSetupAdminAccounts"]) > 0

    if not auto_populate and not auto_setup:
        # nothing to do
        return

    payload["LockPrimaryAccountInfo"] = auto_populate
    payload["SkipPrimarySetupAccountCreation"] = not auto_populate

    # remove existing queued AccountConfiguration command
    DeviceCommand.objects.filter(enrolled_device=enrolled_device,
                                 request_type="AccountConfiguration",
                                 time__isnull=True).delete()
    # queue new command
    build_device_command(enrolled_device, "AccountConfiguration", payload, queue=True)
