from datetime import datetime, timedelta
import logging
from django.db.models import Q
from django.http import HttpResponse
from django.utils import timezone
from zentral.contrib.mdm.apps_books import ensure_enrolled_device_location_asset_association
from zentral.contrib.mdm.models import (Artifact,
                                        Blueprint, Command,
                                        RequestStatus, Platform,
                                        DeviceCommand, ReEnrollmentSession)
from .account_configuration import AccountConfiguration
from .base import registered_commands, load_command
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
from .remove_application import RemoveApplication
from .remove_profile import RemoveProfile
from .security_info import SecurityInfo


logger = logging.getLogger("zentral.contrib.mdm.commands.scheduling")


# Next command


def _update_inventory(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    if not target.is_device:
        return
    blueprint = target.blueprint
    if not blueprint:
        return
    enrolled_device = target.enrolled_device
    min_date = datetime.utcnow() - timedelta(seconds=blueprint.inventory_interval)
    # device information
    if (
        enrolled_device.device_information_updated_at is None
        or enrolled_device.device_information_updated_at < min_date
    ):
        return DeviceInformation.create_for_target(target)
    # security info
    if (
        enrolled_device.security_info_updated_at is None
        or enrolled_device.security_info_updated_at < min_date
    ):
        return SecurityInfo.create_for_target(target)
    # apps
    if (
        blueprint.collect_apps > Blueprint.InventoryItemCollectionOption.NO
        and (
            enrolled_device.apps_updated_at is None
            or enrolled_device.apps_updated_at < min_date
        )
    ):
        return InstalledApplicationList.create_for_target(
            target,
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
        return CertificateList.create_for_target(
            target,
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
        return ProfileList.create_for_target(
            target,
            kwargs={
                "managed_only": blueprint.collect_profiles == Blueprint.InventoryItemCollectionOption.MANAGED_ONLY,
                "update_inventory": True
            }
        )


def _get_next_queued_command(target, enrollment_session, status):
    kwargs = {}
    command_model, kwargs = target.get_db_command_model_and_kwargs()
    queryset = (command_model.objects.select_for_update()
                                     .filter(Q(not_before__isnull=True) | Q(not_before__lte=timezone.now())))
    if status == RequestStatus.NOT_NOW:
        # only schedule new commands
        queryset = queryset.filter(time__isnull=True)
    else:
        # reschedule not now commands too
        reschedule_db_names = [db_name for db_name, cls in registered_commands.items() if cls.reschedule_notnow]
        queryset = queryset.filter(
            Q(time__isnull=True) | Q(status=RequestStatus.NOT_NOW, name__in=reschedule_db_names)
        )
    db_command = queryset.filter(**kwargs).order_by("created_at").first()
    if db_command:
        command = load_command(db_command)
        command.set_time()
        return command


def _configure_dep_enrollment_accounts(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    if not target.is_device:
        return
    if target.platform != Platform.MACOS:
        return
    if not target.awaiting_configuration:
        return
    dep_enrollment = getattr(enrollment_session, "dep_enrollment", None)
    if not dep_enrollment:
        # should never happen
        logger.error("Enrolled device %s AwaintingConfiguration but no DEP enrollment", target.udid)
        return
    if not dep_enrollment.requires_account_configuration():
        return
    if DeviceCommand.objects.filter(name=AccountConfiguration.get_db_name(),
                                    enrolled_device=target.enrolled_device,
                                    status=Command.Status.ACKNOWLEDGED).count():
        # account configuration already done
        return
    return AccountConfiguration.create_for_target(target)


def _reenroll(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    if not target.is_device:
        return
    enrolled_device = target.enrolled_device
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


def _install_artifacts(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    included_types = None
    if target.declarative_management:
        # device profiles managed using declarative management
        included_types = (Artifact.Type.ENTERPRISE_APP, Artifact.Type.STORE_APP)
    artifact_version = target.next_to_install(included_types=included_types)
    if artifact_version:
        command_class = None
        if artifact_version.artifact.type == Artifact.Type.PROFILE:
            command_class = InstallProfile
        elif artifact_version.artifact.type == Artifact.Type.ENTERPRISE_APP:
            command_class = InstallEnterpriseApplication
        elif artifact_version.artifact.type == Artifact.Type.STORE_APP:
            # on-the-fly asset assignment
            if ensure_enrolled_device_location_asset_association(
                target.enrolled_device,
                artifact_version.store_app.location_asset
            ):
                # the association is already done, we can send the command
                command_class = InstallApplication
        else:
            # should never happen
            raise ValueError(f"Cannot install artifact type {artifact_version.artifact.type}")
        if command_class:
            return command_class.create_for_target(target, artifact_version)


def _remove_artifacts(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    included_types = None
    if target.declarative_management:
        # device profiles managed using declarative management
        included_types = (Artifact.Type.STORE_APP,)
    artifact_version = target.next_to_remove(included_types=included_types)
    if artifact_version:
        if artifact_version.artifact.type == Artifact.Type.PROFILE:
            command_class = RemoveProfile
        elif artifact_version.artifact.type == Artifact.Type.STORE_APP:
            command_class = RemoveApplication
        else:
            # should never happen
            raise ValueError(f"Cannot remove artifact type {artifact_version.artifact.type}")
        return command_class.create_for_target(target, artifact_version)


def _trigger_declarative_management_sync(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    if not DeclarativeManagement.verify_target(target):
        return
    _, declarations_token = target.sync_tokens
    if (
        not target.declarative_management
        or target.current_declarations_token != declarations_token
    ):
        return DeclarativeManagement.create_for_target(target)


def _finish_dep_enrollment_configuration(target, enrollment_session, status):
    if status == RequestStatus.NOT_NOW:
        return
    if not target.is_device:
        return
    if not target.awaiting_configuration:
        return
    return DeviceConfigured.create_for_target(target)


def get_next_command_response(target, enrollment_session, status):
    for next_command_func in (
        # first, take care of all the pending commands
        _get_next_queued_command,
        # no pending commands, we can create new ones
        _update_inventory,
        _reenroll,
        _trigger_declarative_management_sync,
        _install_artifacts,
        _remove_artifacts,
        _configure_dep_enrollment_accounts,
        _finish_dep_enrollment_configuration
    ):
        command = next_command_func(target, enrollment_session, status)
        if command:
            return command.build_http_response(enrollment_session)
    return HttpResponse()
