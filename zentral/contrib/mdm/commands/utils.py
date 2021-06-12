import logging
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.models import (ArtifactType, ArtifactVersion,
                                        Channel, CommandStatus,
                                        DeviceCommand, UserCommand)
from .account_configuration import AccountConfiguration
from .declarative_management import DeclarativeManagement
from .device_configured import DeviceConfigured
from .install_profile import InstallProfile
from .install_enterprise_application import InstallEnterpriseApplication
from .remove_profile import RemoveProfile
from .base import registered_commands


logger = logging.getLogger("zentral.contrib.mdm.commands.utils")


def get_command(channel, uuid):
    if channel == Channel.Device:
        db_model_class = DeviceCommand
    else:
        db_model_class = UserCommand
    try:
        db_command = (db_model_class.objects.select_related("artifact_version__artifact",
                                                            "artifact_version__enterprise_app",
                                                            "artifact_version__profile")
                                            .get(uuid=uuid))
    except db_model_class.DoesNotExist:
        logger.error("Unknown command: %s %s", channel.name, uuid)
        return
    try:
        model_class = registered_commands[db_command.name]
    except KeyError:
        logger.error("Unknown command model class: %s", db_command.name)
    else:
        return model_class(channel, db_command)


def load_command(db_command):
    try:
        model_class = registered_commands[db_command.name]
    except KeyError:
        raise ValueError(f"Unknown command model class: {db_command.name}")
    if isinstance(db_command, DeviceCommand):
        return model_class(Channel.Device, db_command)
    else:
        return model_class(Channel.User, db_command)


# Next command


def _get_next_queued_command(channel, enrollment_session, enrolled_device, enrolled_user):
    kwargs = {}
    if channel == Channel.Device:
        command_model = DeviceCommand
        kwargs["enrolled_device"] = enrolled_device
    else:
        command_model = UserCommand
        kwargs["enrolled_user"] = enrolled_user
    # TODO reschedule the NotNow commands
    queryset = (command_model.objects.select_for_update()
                                     .filter(time__isnull=True)
                                     .filter(Q(not_before__isnull=True) | Q(not_before__lte=timezone.now())))
    db_command = queryset.filter(**kwargs).order_by("created_at").first()
    if db_command:
        command = load_command(db_command)
        command.set_time()
        return command


def _configure_dep_enrollment_accounts(channel, enrollment_session, enrolled_device, enrolled_user):
    if channel != Channel.Device:
        return
    if not enrolled_device.awaiting_configuration:
        return
    dep_enrollment = getattr(enrollment_session, "dep_enrollment", None)
    if not dep_enrollment:
        # should never happen
        logger.error("Enrolled device %s AwaintingConfiguration but no DEP enrollment", enrolled_device.udid)
        return
    if not dep_enrollment.requires_account_configuration():
        return
    realm_user = enrollment_session.realm_user
    if not realm_user:
        # should never happen
        logger.error("Enrolled device %s AwaintingConfiguration with missing realm user", enrolled_device.udid)
        return
    if DeviceCommand.objects.filter(name=AccountConfiguration.request_type,
                                    enrolled_device=enrolled_device,
                                    status=CommandStatus.Acknowledged.value).count():
        # account configuration already done
        return
    return AccountConfiguration.create_for_device(enrolled_device)


def _renew_mdm_payload(channel, enrollment_session, enrolled_device, enrolled_user):
    if channel != Channel.Device:
        return
    # TODO implement MDM payload renewal


def _install_artifacts(channel, enrollment_session, enrolled_device, enrolled_user):
    if enrolled_device.declarative_management:
        return
    if channel == Channel.Device:
        target = enrolled_device
    else:
        target = enrolled_user
    artifact_version = ArtifactVersion.objects.next_to_install(target)
    if artifact_version:
        if artifact_version.artifact.type == ArtifactType.Profile.name:
            command_class = InstallProfile
        elif artifact_version.artifact.type == ArtifactType.EnterpriseApp.name:
            command_class = InstallEnterpriseApplication
        else:
            # should never happen
            raise ValueError(f"Cannot install artifact type {artifact_version.artifact.type}")
        if channel == Channel.Device:
            return command_class.create_for_device(enrolled_device, artifact_version)
        else:
            return command_class.create_for_user(enrolled_user, artifact_version)


def _remove_artifacts(channel, enrollment_session, enrolled_device, enrolled_user):
    if enrolled_device.declarative_management:
        return
    if channel == Channel.Device:
        target = enrolled_device
    else:
        target = enrolled_user
    artifact_version = ArtifactVersion.objects.next_to_remove(target)
    if artifact_version:
        if artifact_version.artifact.type == ArtifactType.Profile.name:
            command_class = RemoveProfile
        else:
            # should never happen
            raise ValueError(f"Cannot remove artifact type {artifact_version.artifact.type}")
        if channel == Channel.Device:
            return command_class.create_for_device(enrolled_device, artifact_version)
        else:
            return command_class.create_for_user(enrolled_user, artifact_version)


def _trigger_declarative_management(channel, enrollment_session, enrolled_device, enrolled_user):
    if not enrolled_device.declarative_management:
        return
    if channel != Channel.Device:
        return
    if (
        enrolled_device.blueprint
        and enrolled_device.declarations_token != enrolled_device.blueprint.declarations_token
    ):
        return DeclarativeManagement.create_for_device(enrolled_device)


def _finish_dep_enrollment_configuration(channel, enrollment_session, enrolled_device, enrolled_user):
    if channel != Channel.Device:
        return
    if not enrolled_device.awaiting_configuration:
        return
    return DeviceConfigured.create_for_device(enrolled_device)


def get_next_command_response(channel, enrollment_session, enrolled_device, enrolled_user):
    for next_command_func in (_get_next_queued_command,
                              _configure_dep_enrollment_accounts,
                              _renew_mdm_payload,
                              _install_artifacts,
                              _remove_artifacts,
                              _trigger_declarative_management,
                              _finish_dep_enrollment_configuration):
        command = next_command_func(channel, enrollment_session, enrolled_device, enrolled_user)
        if command:
            return command.build_http_response(enrollment_session)
    return HttpResponse()
