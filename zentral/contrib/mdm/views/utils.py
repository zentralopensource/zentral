import copy
import logging
import plistlib
import os.path
from django.contrib.contenttypes.models import ContentType
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils import timezone
from zentral.conf import settings
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.mdm.commands import (build_install_application_command_response,
                                          build_install_profile_command_response,
                                          build_remove_profile_command_response)
from zentral.contrib.mdm.models import (DeviceArtifactCommand, InstalledDeviceArtifact,
                                        KernelExtensionPolicy, MDMEnrollmentPackage, ConfigurationProfile)


logger = logging.getLogger("zentral.contrib.mdm.views.utils")


def tree_from_payload(udid, serial_number, meta_business_unit, payload):
    url = reverse("mdm:device", args=(MetaMachine(serial_number).get_urlsafe_serial_number(),))
    tree = {"source": {"module": "zentral.contrib.mdm",
                       "name": "MDM"},
            "reference": udid,
            "serial_number": serial_number,
            "links": [{"anchor_text": "info", "url": url}]}

    # Mobile device IDs
    for attr in ("IMEI", "MEID"):
        val = payload.get(attr)
        if val:
            tree[attr.lower()] = val

    # BU
    try:
        tree["business_unit"] = meta_business_unit.api_enrollment_business_units()[0].serialize()
    except IndexError:
        pass

    # OS Version
    os_version = payload.get("OSVersion")
    build_version = payload.get("BuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if build_version:
            d["build"] = build_version
        tree["os_version"] = d

    # System Info
    system_info_d = {}
    for si_attr, attr in (("computer_name", "DeviceName"),
                          ("hardware_model", "ModelName"),
                          ("hardware_serial", "Model"),
                          ("hardware_serial", "ProductName")):
        val = payload.get(attr)
        if val:
            system_info_d[si_attr] = val
    if system_info_d:
        tree["system_info"] = system_info_d

    # OS Version
    os_version = payload.get("OSVersion")
    build_version = payload.get("BuildVersion")
    if os_version:
        d = dict(zip(('major', 'minor', 'patch'),
                     (int(s) for s in os_version.split('.'))))
        if build_version:
            d["build"] = build_version
        hardware_model = system_info_d.get("hardware_model")
        if hardware_model:
            hardware_model = hardware_model.upper()
            if "IPOD" in hardware_model or "IPAD" in hardware_model or "IPHONE" in hardware_model:
                d["name"] = "iOS"
            elif "WATCH" in hardware_model:
                d["name"] = "watchOS"
            elif "TV" in hardware_model:
                d["name"] = "tvOS"
            else:
                d["name"] = "macOS"
        tree["os_version"] = d
    return tree


def parse_dn(dn):
    # TODO: poor man's DN parser
    d = {}
    current_attr = ""
    current_val = ""

    state = "ATTR"
    string_state = "NOT_ESCAPED"
    for c in dn:
        if c == "\\" and string_state == "NOT_ESCAPED":
            string_state = "ESCAPED"
        else:
            if string_state == "NOT_ESCAPED" and c in "=,":
                if c == "=":
                    state = "VAL"
                elif c == ",":
                    state = "ATTR"
                    if current_attr:
                        d[current_attr] = current_val
                    current_attr = current_val = ""
            else:
                if state == "ATTR":
                    current_attr += c
                elif state == "VAL":
                    current_val += c
                if string_state == "ESCAPED":
                    string_state = "NOT_ESCAPED"

    if current_attr:
        d[current_attr] = current_val
        current_attr = current_val = ""
    return d


# next command


def get_configured_device_artifact_dict(meta_business_unit, serial_number):
    artifact_version_dict = {}

    # MBU KernelExtensionPolicy
    try:
        artifact = KernelExtensionPolicy.objects.get(meta_business_unit=meta_business_unit,
                                                     trashed_at__isnull=True)
    except KernelExtensionPolicy.DoesNotExist:
        pass
    else:
        kext_policy_ct = ContentType.objects.get_for_model(artifact)
        artifact_version_dict.setdefault(kext_policy_ct, {})[artifact.pk] = artifact.version

    # MBU MDMEnrollmentPackage
    mdm_enrollment_package_ct = ContentType.objects.get_for_model(MDMEnrollmentPackage)
    for artifact in MDMEnrollmentPackage.objects.filter(meta_business_unit=meta_business_unit,
                                                        trashed_at__isnull=True):
        artifact_version_dict.setdefault(mdm_enrollment_package_ct, {})[artifact.pk] = artifact.version

    # MBU ConfigurationProfile
    configuration_profile_ct = ContentType.objects.get_for_model(ConfigurationProfile)
    for artifact in ConfigurationProfile.objects.filter(meta_business_unit=meta_business_unit,
                                                        trashed_at__isnull=True):
        artifact_version_dict.setdefault(configuration_profile_ct, {})[artifact.pk] = artifact.version

    return artifact_version_dict


def get_installed_device_artifact_dict(enrolled_device):
    artifact_version_dict = {}
    for ida in (InstalledDeviceArtifact.objects.select_related("artifact_content_type")
                                               .filter(enrolled_device=enrolled_device)):
        artifact_ct = ida.artifact_content_type
        if artifact_ct not in artifact_version_dict:
            artifact_version_dict[artifact_ct] = {}
        artifact_version_dict[artifact_ct][ida.artifact_id] = ida.artifact_version
    return artifact_version_dict


def iter_next_device_artifact_actions(meta_business_unit, enrolled_device):
    """Compute the actions necessary to achieve the configured device state"""
    configured_device_artifact_dict = get_configured_device_artifact_dict(meta_business_unit,
                                                                          enrolled_device.serial_number)
    installed_device_artifact_dict = get_installed_device_artifact_dict(enrolled_device)

    # find all not installed or stalled artifacts
    for artifact_ct, artifact_ct_version_dict in configured_device_artifact_dict.items():
        installed_artifact_ct_dict = installed_device_artifact_dict.get(artifact_ct, {})
        for configured_artifact_id, configured_artifact_version in artifact_ct_version_dict.items():
            installed_artifact_version = installed_artifact_ct_dict.get(configured_artifact_id, -1)
            if installed_artifact_version < configured_artifact_version:
                yield (DeviceArtifactCommand.ACTION_INSTALL,
                       artifact_ct,
                       artifact_ct.get_object_for_this_type(pk=configured_artifact_id))

    # find all installed artifacts that need to be removed
    for artifact_ct, artifact_ct_version_dict in installed_device_artifact_dict.items():
        artifact_model_class = artifact_ct.model_class()
        if not getattr(artifact_model_class, "artifact_can_be_removed", True):
            # skip these artifacts, because they cannot be removed
            continue
        configured_artifact_ct_dict = configured_device_artifact_dict.get(artifact_ct, {})
        for artifact_id in artifact_ct_version_dict.keys():
            if artifact_id not in configured_artifact_ct_dict:
                yield (DeviceArtifactCommand.ACTION_REMOVE,
                       artifact_ct,
                       artifact_ct.get_object_for_this_type(pk=artifact_id))


def get_next_device_artifact_command_response(meta_business_unit, enrolled_device):
    for action, artifact_ct, artifact in iter_next_device_artifact_actions(meta_business_unit, enrolled_device):
        # If we have an error with this artifact, we skip it.
        # In order to try again, we will have to bump the artifact version.
        # We do not care if we already have a command without an answer.
        # TODO: really OK ???
        device_artifact_command_d = {"enrolled_device": enrolled_device,
                                     "artifact_content_type": artifact_ct,
                                     "artifact_id": artifact.pk,
                                     "artifact_version": artifact.version,
                                     "action": action}
        if DeviceArtifactCommand.objects.filter(**device_artifact_command_d,
                                                status_code__in=("Error", "CommandFormatError")).count():
            # skip this one
            continue
        # create the command
        device_artifact_command_d["command_time"] = timezone.now()
        device_artifact_command = DeviceArtifactCommand.objects.create(**device_artifact_command_d)
        command_uuid = device_artifact_command.command_uuid
        # return the adequate response
        if artifact.artifact_type == "ConfigurationProfile":
            if action == DeviceArtifactCommand.ACTION_INSTALL:
                return build_install_profile_command_response(artifact, command_uuid)
            elif action == DeviceArtifactCommand.ACTION_REMOVE:
                return build_remove_profile_command_response(artifact, command_uuid)
        elif artifact.artifact_type == "Application":
            if action == DeviceArtifactCommand.ACTION_INSTALL:
                return build_install_application_command_response(command_uuid)
        raise NotImplementedError("Missing command {} {}".format(artifact.artifact_type, action))


def get_next_device_command_response(meta_business_unit, enrolled_device):
    response = get_next_device_artifact_command_response(meta_business_unit, enrolled_device)
    if not response:
        response = HttpResponse()
    return response


# InstallApplication


def build_application_manifest_response(command_uuid):
    device_artifact_command = get_object_or_404(DeviceArtifactCommand, command_uuid=command_uuid)
    artifact = device_artifact_command.artifact
    manifest = copy.deepcopy(artifact.manifest)
    download_url = "{}{}".format(settings["api"]["tls_hostname"],
                                 reverse("mdm:install_application_download",
                                         args=(str(device_artifact_command.command_uuid),
                                               os.path.basename(artifact.file.name))))
    manifest["items"][0]["assets"][0]["url"] = download_url
    return HttpResponse(plistlib.dumps(manifest),
                        content_type="text/xml; charset=UTF-8")


def build_application_download_response(command_uuid):
    device_artifact_command = get_object_or_404(DeviceArtifactCommand, command_uuid=command_uuid)
    package_file = device_artifact_command.artifact.file
    response = FileResponse(package_file, content_type="application/octet-stream")
    response["Content-Length"] = package_file.size
    response["Content-Disposition"] = 'attachment;filename="{}"'.format(os.path.basename(package_file.name))
    return response


# process result payload


def update_device_artifact_command(enrolled_device, command_uuid, payload_status):
    # find command
    try:
        device_artifact_command = DeviceArtifactCommand.objects.get(
            enrolled_device=enrolled_device,
            command_uuid=command_uuid
        )
    except DeviceArtifactCommand.DoesNotExist:
        return

    # update command
    device_artifact_command.status_code = payload_status
    device_artifact_command.result_time = timezone.now()
    device_artifact_command.save()

    # if acknowledged, update installed device artifacts
    if payload_status == DeviceArtifactCommand.STATUS_CODE_ACKNOWLEDGED:
        if device_artifact_command.action == DeviceArtifactCommand.ACTION_INSTALL:
            # a new version of the artifact has been installed on the device
            InstalledDeviceArtifact.objects.update_or_create(
                enrolled_device=enrolled_device,
                artifact_content_type=device_artifact_command.artifact_content_type,
                artifact_id=device_artifact_command.artifact_id,
                defaults={
                  "artifact_version": device_artifact_command.artifact_version
                }
            )
        else:
            # the artifact has been removed from the device
            InstalledDeviceArtifact.objects.filter(
                enrolled_device=enrolled_device,
                artifact_content_type=device_artifact_command.artifact_content_type,
                artifact_id=device_artifact_command.artifact_id
            ).delete()

    return device_artifact_command


def commit_device_information_command_response(meta_business_unit, enrolled_device, payload):
    query_responses = payload.get("QueryResponses")
    if query_responses:
        return commit_machine_snapshot_and_trigger_events(tree_from_payload(enrolled_device.udid,
                                                                            enrolled_device.serial_number,
                                                                            meta_business_unit,
                                                                            query_responses))


def process_result_payload(meta_business_unit, enrolled_device, command_uuid, payload_status, payload):
    # TODO: much better !
    if update_device_artifact_command(enrolled_device, command_uuid, payload_status):
        return
    if commit_device_information_command_response(meta_business_unit, enrolled_device, payload):
        return
