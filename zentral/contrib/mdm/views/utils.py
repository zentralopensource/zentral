from datetime import timedelta
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
from zentral.contrib.mdm.commands import (build_device_command_response,
                                          build_device_configured_command,
                                          build_device_information_command,
                                          build_install_application_command,
                                          build_install_profile_command,
                                          build_remove_profile_command)
from zentral.contrib.mdm.models import (DeviceCommand, DeviceArtifactCommand, InstalledDeviceArtifact,
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


# next command


def get_configured_device_artifact_dict(meta_business_unit, enrolled_device):
    artifact_version_dict = {}

    artifact_search_dict = {"meta_business_unit": meta_business_unit,
                            "trashed_at__isnull": True}
    if enrolled_device.awaiting_configuration:
        artifact_search_dict["install_before_setup_assistant"] = True

    for artifact_model in (KernelExtensionPolicy, MDMEnrollmentPackage, ConfigurationProfile):
        artifact_ct = ContentType.objects.get_for_model(artifact_model)
        for artifact in artifact_model.objects.filter(**artifact_search_dict):
            artifact_version_dict.setdefault(artifact_ct, {})[artifact.pk] = artifact.version

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
    configured_device_artifact_dict = get_configured_device_artifact_dict(meta_business_unit, enrolled_device)
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
        # build the device command
        device_command = None
        if artifact.artifact_type == "ConfigurationProfile":
            if action == DeviceArtifactCommand.ACTION_INSTALL:
                device_command = build_install_profile_command(enrolled_device, artifact)
            elif action == DeviceArtifactCommand.ACTION_REMOVE:
                device_command = build_remove_profile_command(enrolled_device, artifact)
        elif artifact.artifact_type == "Application":
            if action == DeviceArtifactCommand.ACTION_INSTALL:
                device_command = build_install_application_command(enrolled_device)
        if device_command is None:
            raise NotImplementedError("Missing command {} {}".format(artifact.artifact_type, action))
        else:
            # build the device artifact command linked to the command
            device_artifact_command_d["command"] = device_command
            DeviceArtifactCommand.objects.create(**device_artifact_command_d)
            # return the command response
            return build_device_command_response(device_command)


def get_next_queued_device_command_response(enrolled_device):
    for device_command in (DeviceCommand.objects.filter(enrolled_device=enrolled_device,
                                                        time__isnull=True)  # queued
                                                .order_by("created_at")):
        # dequeue device command
        # TODO: BETTER
        device_command.time = timezone.now()
        device_command.save()
        return build_device_command_response(device_command)


def get_next_device_command_response(meta_business_unit, enrolled_device):
    # queued commands
    response = get_next_queued_device_command_response(enrolled_device)
    if response:
        return response
    # artifacts to install or remove
    response = get_next_device_artifact_command_response(meta_business_unit, enrolled_device)
    if response:
        return response
    elif enrolled_device.awaiting_configuration:
        # no queued commands + no artifacts to install or remove + AwaitingConfiguration
        # let's proceed to the next step in the DEP enrollement
        # → DeviceConfigured
        return build_device_command_response(build_device_configured_command(enrolled_device))
    elif not DeviceCommand.objects.filter(enrolled_device=enrolled_device,
                                          request_type="DeviceInformation",
                                          time__gt=(timezone.now() - timedelta(days=1))).count():
        # no recent information, get some
        return build_device_command_response(build_device_information_command(enrolled_device))
    else:
        # nothing else to do
        return HttpResponse()


# InstallApplication


def build_application_manifest_response(command_uuid):
    device_artifact_command = get_object_or_404(DeviceArtifactCommand, command__uuid=command_uuid)
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
    device_artifact_command = get_object_or_404(DeviceArtifactCommand, command__uuid=command_uuid)
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
            command__enrolled_device=enrolled_device,
            command__uuid=command_uuid
        )
    except DeviceArtifactCommand.DoesNotExist:
        return

    # update device command
    device_command = device_artifact_command.command
    device_command.status_code = payload_status
    device_command.result_time = timezone.now()
    device_command.save()

    # if acknowledged, update installed device artifacts
    if payload_status == DeviceCommand.STATUS_CODE_ACKNOWLEDGED:
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


def update_device_command(meta_business_unit, enrolled_device, command_uuid, payload_status, payload):
    # less specific than update_device_artifact_command. MUST RUN AFTERWARD.

    # find command
    try:
        device_command = DeviceCommand.objects.get(
            enrolled_device=enrolled_device,
            uuid=command_uuid
        )
    except DeviceCommand.DoesNotExist:
        logger.exception("Could not find device command %s", command_uuid)
        return

    # update device command
    device_command.status_code = payload_status
    device_command.result_time = timezone.now()
    device_command.save()

    request_type = device_command.request_type
    if request_type == "DeviceConfigured":
        if payload_status == DeviceCommand.STATUS_CODE_ACKNOWLEDGED:
            if enrolled_device.awaiting_configuration:
                enrolled_device.awaiting_configuration = False
                enrolled_device.save()
            else:
                logger.error("Enrolled device %s is not awaiting configuration!",
                             enrolled_device.udid)
        else:
            logger.error("DeviceConfigured command unexpected status %s for device %s",
                         payload_status, enrolled_device.udid)
    elif request_type == "DeviceInformation":
        query_responses = payload.get("QueryResponses")
        if query_responses:
            return commit_machine_snapshot_and_trigger_events(tree_from_payload(enrolled_device.udid,
                                                                                enrolled_device.serial_number,
                                                                                meta_business_unit,
                                                                                query_responses))
        else:
            logger.error("Empty or absent QueryResponses in a DeviceInformation response.")

    return device_command


def process_result_payload(meta_business_unit, enrolled_device, command_uuid, payload_status, payload):
    # TODO: much better !
    if update_device_artifact_command(enrolled_device, command_uuid, payload_status):
        return
    if update_device_command(meta_business_unit, enrolled_device, command_uuid, payload_status, payload):
        return
