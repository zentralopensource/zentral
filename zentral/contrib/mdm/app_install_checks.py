from django.db.models import Exists, OuterRef, Q
from .apns import send_enrolled_device_notification, send_enrolled_user_notification
from .artifacts import Target
from .commands.installed_application_list import InstalledApplicationList
from .commands.managed_application_list import ManagedApplicationList
from .models import Artifact, Command, DeviceArtifact, DeviceCommand, TargetArtifact, UserArtifact, UserCommand


APP_ARTIFACT_TYPES = (Artifact.Type.STORE_APP, Artifact.Type.ENTERPRISE_APP)
APP_INSTALL_CHECK_COMMAND_NAMES = (ManagedApplicationList.get_db_name(), InstalledApplicationList.get_db_name())


class AppInstallCheckError(Exception):
    pass


def _unchecked_app_target_artifacts(ta_model, cmd_model, target_field, device_lookup, serial_numbers=None):
    # A check that is queued, in flight, or answered NotNow is sent or re-sent at the next
    # connection, so the target artifact is still being watched.
    pending_check = cmd_model.objects.filter(
        **{target_field: OuterRef(target_field)},
        artifact_version=OuterRef("artifact_version"),
        name__in=APP_INSTALL_CHECK_COMMAND_NAMES,
    ).filter(Q(time__isnull=True) | Q(result_time__isnull=True) | Q(status=Command.Status.NOT_NOW))
    qs = (ta_model.objects
          .filter(status=TargetArtifact.Status.AWAITING_CONFIRMATION,
                  artifact_version__artifact__type__in=APP_ARTIFACT_TYPES)
          .annotate(pending_check=Exists(pending_check))
          .filter(pending_check=False)
          .select_related("artifact_version__artifact",
                          "artifact_version__store_app__location_asset__asset",
                          "artifact_version__enterprise_app",
                          device_lookup))
    if serial_numbers:
        qs = qs.filter(**{f"{device_lookup}__serial_number__in": serial_numbers})
    return qs.order_by(f"{target_field}_id", "created_at")


def iter_unchecked_app_target_artifacts(serial_numbers=None):
    for target_artifact in _unchecked_app_target_artifacts(
        DeviceArtifact, DeviceCommand, "enrolled_device", "enrolled_device", serial_numbers
    ):
        yield Target(target_artifact.enrolled_device), target_artifact
    for target_artifact in _unchecked_app_target_artifacts(
        UserArtifact, UserCommand, "enrolled_user", "enrolled_user__enrolled_device", serial_numbers
    ):
        enrolled_user = target_artifact.enrolled_user
        yield Target(enrolled_user.enrolled_device, enrolled_user), target_artifact


def get_app_install_check(artifact_version):
    artifact_type = artifact_version.artifact.get_type()
    if artifact_type == Artifact.Type.STORE_APP:
        bundle_id = artifact_version.store_app.location_asset.asset.bundle_id
        if not bundle_id:
            raise AppInstallCheckError("Asset without bundle ID")
        return ManagedApplicationList, {"identifiers": [bundle_id]}
    elif artifact_type == Artifact.Type.ENTERPRISE_APP:
        apps_to_check = [
            {"Identifier": bundle["id"], "ShortVersion": bundle["version_str"]}
            for bundle in artifact_version.enterprise_app.bundles
        ]
        if not apps_to_check:
            raise AppInstallCheckError("Enterprise app without bundles")
        return InstalledApplicationList, {"apps_to_check": apps_to_check}
    raise AppInstallCheckError(f"Unsupported artifact type {artifact_type}")


def queue_app_install_check(target, artifact_version):
    command_class, kwargs = get_app_install_check(artifact_version)
    if not command_class.verify_target(target):
        raise AppInstallCheckError(f"Incompatible target for {command_class.get_db_name()}")
    return command_class.create_for_target(target, artifact_version, kwargs=kwargs, queue=True)


def notify_target(target):
    if not target.enrolled_device.can_be_poked():
        return False
    if target.is_device:
        success, _ = send_enrolled_device_notification(target.enrolled_device)
    else:
        success, _ = send_enrolled_user_notification(target.enrolled_user)
    return success
