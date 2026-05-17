from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace
from pbac.types import LEGACY_PERM_APPLIES_TO


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
    "mdm.disown_depdevice",
    applies_to=LEGACY_PERM_APPLIES_TO,
)


view_admin_password_action = engine.register_action(
    "viewAdminPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_admin_password",
    applies_to=LEGACY_PERM_APPLIES_TO,
)


view_device_lock_pin_action = engine.register_action(
    "viewDeviceLockPIN",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_device_lock_pin",
    applies_to=LEGACY_PERM_APPLIES_TO,
)


view_filevaul_prk_action = engine.register_action(
    "viewFileVaultPRK",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_filevault_prk",
    applies_to=LEGACY_PERM_APPLIES_TO,
)


view_recovery_password_action = engine.register_action(
    "viewRecoveryPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_recovery_password",
    applies_to=LEGACY_PERM_APPLIES_TO,
)
