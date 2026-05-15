from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace


# namespace


NAMESPACE_ID = "MDM"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions


disown_dep_device_action = engine.get_action(
    "disownDEPDevice",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.disown_depdevice",
)


view_admin_password_action = engine.get_action(
    "viewAdminPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_admin_password",
)


view_device_lock_pin_action = engine.get_action(
    "viewDeviceLockPIN",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_device_lock_pin",
)


view_filevaul_prk_action = engine.get_action(
    "viewFileVaultPRK",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_filevault_prk",
)


view_recovery_password_action = engine.get_action(
    "viewRecoveryPassword",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    "mdm.view_recovery_password",
)
