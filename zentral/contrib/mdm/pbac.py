from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request
from pbac.types import (
    LEGACY_PERM_APPLIES_TO,
    SERVICE_ACCOUNT,
    USER,
    AppliesTo,
    AttrSpec,
)

from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.pbac import MACHINE_RESOURCE_TYPE, get_meta_machine_resource

from .models import Artifact, Channel


# namespace


NAMESPACE_ID = "MDM"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions
#
# These five custom actions are only reachable today via the legacy-perm
# path (e.g. user.has_perm("mdm.view_admin_password")), which constructs
# a Request against engine.system_any_resource with an empty context.
# applies_to therefore matches LEGACY_PERM_APPLIES_TO (principal: User or
# ServiceAccount, resource: System, no context). A future typed PBAC path
# would tighten applies_to to the relevant resource (e.g. EnrolledDevice).


disown_dep_device_action = engine.register_action(
    "disownDEPDevice",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="mdm.disown_depdevice",
    help_text="Disown a DEP device. Apple removes the device from the organization.",
)


view_admin_password_action = engine.register_action(
    "viewAdminPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="mdm.view_admin_password",
    help_text="See the password of the local administrator account that Zentral created on a device.",
)


view_device_lock_pin_action = engine.register_action(
    "viewDeviceLockPIN",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="mdm.view_device_lock_pin",
    help_text="See the PIN that unlocks a device that Zentral locked.",
)


view_filevaul_prk_action = engine.register_action(
    "viewFileVaultPRK",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="mdm.view_filevault_prk",
    help_text="See the FileVault personal recovery key of a device. The key can rotate after it is seen.",
)


view_recovery_password_action = engine.register_action(
    "viewRecoveryPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=LEGACY_PERM_APPLIES_TO,
    legacy_perm="mdm.view_recovery_password",
    help_text="See the recovery lock or firmware password of a device. The password can rotate after it "
              "is seen.",
)


# forceInstallArtifact takes the inventory machine resource, so a policy can be scoped to a
# meta business unit. It carries no legacy_perm: the typed PBAC path is the only way in, and
# every context attribute is required, so a policy can read them without a has guard.
force_install_artifact_action = engine.register_action(
    "forceInstallArtifact",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(MACHINE_RESOURCE_TYPE,),
        context={
            "artifactType": AttrSpec(
                str,
                help_text="The type of the artifact.",
                values=Artifact.Type.values,
            ),
            "artifactID": AttrSpec(
                str,
                help_text="The primary key of the artifact, as a UUID string.",
            ),
            "artifactName": AttrSpec(
                str,
                help_text="The name of the artifact.",
            ),
            "channel": AttrSpec(
                str,
                help_text="The channel of the target the artifact installs on.",
                values=Channel.values,
            ),
        },
    ),
    help_text="Force a new install attempt of an artifact on a machine.",
)


# requests


class ForceInstallArtifactRequest(Request):
    def __init__(self, user_obj, machine: MetaMachine, artifact, channel) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            force_install_artifact_action,
            get_meta_machine_resource(machine),
            {"artifactType": artifact.type,
             "artifactID": str(artifact.pk),
             "artifactName": artifact.name,
             "channel": str(channel)},
        )
