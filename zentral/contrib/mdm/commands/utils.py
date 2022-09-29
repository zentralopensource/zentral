from datetime import datetime, timedelta
import logging
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.apps_books import ensure_enrolled_device_asset_association
from zentral.contrib.mdm.models import (ArtifactType, ArtifactVersion,
                                        Blueprint, CommandStatus,
                                        Channel, RequestStatus, Platform,
                                        DeviceCommand, ReEnrollmentSession, UserCommand)
from .account_configuration import AccountConfiguration
from .base import registered_commands
from .certificate_list import CertificateList
from .declarative_management import DeclarativeManagement
from .device_configured import DeviceConfigured
from .device_information import DeviceInformation
from .install_application import InstallApplication
from .install_enterprise_application import InstallEnterpriseApplication
from .install_profile import InstallProfile
from .installed_application_list import InstalledApplicationList
from .profile_list import ProfileList
from .reenroll import Reenroll
from .remove_profile import RemoveProfile
from .security_info import SecurityInfo


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


def _update_inventory(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if channel != Channel.Device:
        return
    blueprint = enrolled_device.blueprint
    if not blueprint:
        return
    min_date = datetime.utcnow() - timedelta(seconds=blueprint.inventory_interval)
    # device information
    if (
        enrolled_device.device_information_updated_at is None
        or enrolled_device.device_information_updated_at < min_date
    ):
        return DeviceInformation.create_for_device(enrolled_device)
    # security info
    if (
        enrolled_device.security_info_updated_at is None
        or enrolled_device.security_info_updated_at < min_date
    ):
        return SecurityInfo.create_for_device(enrolled_device)
    # apps
    if (
        blueprint.collect_apps > Blueprint.InventoryItemCollectionOption.NO
        and (
            enrolled_device.apps_updated_at is None
            or enrolled_device.apps_updated_at < min_date
        )
    ):
        return InstalledApplicationList.create_for_device(
            enrolled_device,
            kwargs={
                "managed_only": blueprint.collect_apps == Blueprint.InventoryItemCollectionOption.MANAGED_ONLY,
                "update_inventory": True
            }
        )
    # certificates
    if (
        blueprint.collect_certificates > Blueprint.InventoryItemCollectionOption.NO
        and (
            enrolled_device.certificates_updated_at is None
            or enrolled_device.certificates_updated_at < min_date
        )
    ):
        return CertificateList.create_for_device(
            enrolled_device,
            kwargs={
                "managed_only": blueprint.collect_certificates == Blueprint.InventoryItemCollectionOption.MANAGED_ONLY,
                "update_inventory": True
            }
        )
    # profiles
    if (
        blueprint.collect_profiles > Blueprint.InventoryItemCollectionOption.NO
        and (
            enrolled_device.profiles_updated_at is None
            or enrolled_device.profiles_updated_at < min_date
        )
    ):
        return ProfileList.create_for_device(
            enrolled_device,
            kwargs={
                "managed_only": blueprint.collect_profiles == Blueprint.InventoryItemCollectionOption.MANAGED_ONLY,
                "update_inventory": True
            }
        )


def _get_next_queued_command(channel, status, enrollment_session, enrolled_device, enrolled_user):
    kwargs = {}
    if channel == Channel.Device:
        command_model = DeviceCommand
        kwargs["enrolled_device"] = enrolled_device
    else:
        command_model = UserCommand
        kwargs["enrolled_user"] = enrolled_user
    queryset = (command_model.objects.select_for_update()
                                     .filter(Q(not_before__isnull=True) | Q(not_before__lte=timezone.now())))
    if status == RequestStatus.NotNow:
        # only schedule new commands
        queryset = queryset.filter(time__isnull=True)
    else:
        # reschedule not now commands too
        reschedule_db_names = [db_name for db_name, cls in registered_commands.items() if cls.reschedule_notnow]
        queryset = queryset.filter(
            Q(time__isnull=True) | Q(status=RequestStatus.NotNow.value, name__in=reschedule_db_names)
        )
    db_command = queryset.select_related("artifact_version__artifact").filter(**kwargs).order_by("created_at").first()
    if db_command:
        command = load_command(db_command)
        command.set_time()
        return command


def _configure_dep_enrollment_accounts(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if channel != Channel.Device:
        return
    if enrolled_device.platform != Platform.macOS.value:
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
    if DeviceCommand.objects.filter(name=AccountConfiguration.get_db_name(),
                                    enrolled_device=enrolled_device,
                                    status=CommandStatus.Acknowledged.value).count():
        # account configuration already done
        return
    return AccountConfiguration.create_for_device(enrolled_device)


def _reenroll(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if channel != Channel.Device:
        return
    # TODO configuration for the 90 days and 4 hours
    # no certificate expiry or certificate expiry within the next 90 days
    if (
        enrolled_device.cert_not_valid_after is None
        or enrolled_device.cert_not_valid_after - datetime.utcnow() < timedelta(days=90)
    ):
        # no other re-enrollment session for this enrolled device in the last 4 hours
        if ReEnrollmentSession.objects.filter(enrolled_device=enrolled_device,
                                              created_at__gt=datetime.utcnow() - timedelta(hours=4)).count() == 0:
            return Reenroll.create_for_enrollment_session(enrollment_session)
        else:
            logger.warning("Enrolled device %s needs to re-enroll, but there was at least one re-enrollment session "
                           "in the last 4 hours", enrolled_device.udid)


def _install_artifacts(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if enrolled_device.declarative_management:
        return
    if channel == Channel.Device:
        target = enrolled_device
    else:
        target = enrolled_user
    artifact_version = ArtifactVersion.objects.next_to_install(target)
    if artifact_version:
        command_class = None
        if artifact_version.artifact.type == ArtifactType.Profile.name:
            command_class = InstallProfile
        elif artifact_version.artifact.type == ArtifactType.EnterpriseApp.name:
            command_class = InstallEnterpriseApplication
        elif artifact_version.artifact.type == ArtifactType.StoreApp.name:
            # on-the-fly asset assignment
            if ensure_enrolled_device_asset_association(enrolled_device, artifact_version.store_app.asset):
                # the association is already done, we can send the command
                command_class = InstallApplication
        else:
            # should never happen
            raise ValueError(f"Cannot install artifact type {artifact_version.artifact.type}")
        if command_class:
            if channel == Channel.Device:
                return command_class.create_for_device(enrolled_device, artifact_version)
            else:
                return command_class.create_for_user(enrolled_user, artifact_version)


def _remove_artifacts(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
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


def _trigger_declarative_management_sync(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if not enrolled_device.declarative_management:
        return
    if channel != Channel.Device:
        return
    if (
        enrolled_device.blueprint
        and enrolled_device.declarations_token != enrolled_device.blueprint.declarations_token
    ):
        return DeclarativeManagement.create_for_device(enrolled_device)


def _finish_dep_enrollment_configuration(channel, status, enrollment_session, enrolled_device, enrolled_user):
    if status == RequestStatus.NotNow:
        return
    if channel != Channel.Device:
        return
    if not enrolled_device.awaiting_configuration:
        return
    return DeviceConfigured.create_for_device(enrolled_device)


def get_next_command_response(channel, status, enrollment_session, enrolled_device, enrolled_user):
    for next_command_func in (
        # first, take care of all the pending commands
        _get_next_queued_command,
        # no pending commands, we can create new ones
        _update_inventory,
        _reenroll,
        _install_artifacts,
        _remove_artifacts,
        _trigger_declarative_management_sync,
        _configure_dep_enrollment_accounts,
        _finish_dep_enrollment_configuration
    ):
        command = next_command_func(channel, status, enrollment_session, enrolled_device, enrolled_user)
        if command:
            return command.build_http_response(enrollment_session)
    return HttpResponse()
