from .skip_keys import skippable_setup_panes
from typing import Any
from zentral.utils.os_version import make_comparable_os_version


class DEPEnrollmentValidator:

    def __init__(
            self,
            data: dict[str, Any],
            *args,
            **kwargs):
        self.data = data
        self.errors = {}

    def validate(self):
        # is_mdm_removable
        is_mdm_removable = self.data.get("is_mdm_removable")
        is_supervised = self.data.get("is_supervised")
        if not is_mdm_removable and not is_supervised:
            self.errors.update({"is_mdm_removable": "Can only be set to False if 'Is supervised' is set to True"})

        # use_realm_user
        realm = self.data.get("realm")
        use_realm_user = self.data.get("use_realm_user")
        if use_realm_user and not realm:
            self.errors.update({"use_realm_user": "This option is only valid if a 'realm' is selected"})

        # username_pattern
        username_pattern = self.data.get("username_pattern")
        if not use_realm_user:
            if username_pattern:
                self.errors.update(
                    {"username_pattern": "This field can only be used if the 'use realm user' option is ticked"})
        else:
            if not username_pattern:
                self.errors.update(
                    {"username_pattern": "This field is required when the 'use realm user' option is ticked"})

        # realm_user_is_admin
        realm_user_is_admin = self.data.get("realm_user_is_admin")
        if realm_user_is_admin and not use_realm_user:
            self.errors.update(
                {"realm_user_is_admin": "This option is only valid if the 'use realm user' option is ticked too"})

        # is_max / is_min / macos_max / macos_min
        for platform, limit in [("ios", "max"), ("ios", "min"), ("macos", "max"), ("macos", "min")]:
            fieldname = f"{platform}_{limit}_version"
            os_version = self.data.get(fieldname)
            if os_version and make_comparable_os_version(os_version) == (0, 0, 0):
                self.errors.update({fieldname: "Not a valid OS version"})

        # admin_full_name / admin_short_name / await_device_configured
        if bool(self.data.get("admin_full_name")) ^ bool(self.data.get("admin_short_name")):
            if not self.data.get("admin_full_name"):
                self.errors.update({"admin_full_name": "Auto admin information incomplete"})
            else:
                self.errors.update({"admin_short_name": "Auto admin information incomplete"})
        elif self.data.get("admin_full_name") and not self.data.get("await_device_configured"):
            self.errors.update({"await_device_configured": "Required for the auto admin account setup"})

        # skip_setup_items
        skip_setup_items = self.data.get('skip_setup_items')
        invalid_items = set(skip_setup_items) - {k for k, _ in skippable_setup_panes}
        if invalid_items:
            self.errors.update(
                {"skip_setup_items": f"Unsupported items: {', '.join(invalid_items)}"})

        return self.errors
