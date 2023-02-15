import logging
from realms.utils import serialize_password_hash_dict
from zentral.contrib.mdm.models import Channel, Platform, DEPEnrollmentSession
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.account_configuration")


class AccountConfiguration(Command):
    request_type = "AccountConfiguration"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and not enrolled_device.user_enrollment
        )

    def build_command(self):
        if not isinstance(self.enrollment_session, DEPEnrollmentSession):
            raise ValueError("Invalid enrollment session")
        dep_enrollment = self.enrollment_session.dep_enrollment

        command = {"DontAutoPopulatePrimaryAccountInfo": True,
                   "SkipPrimarySetupAccountCreation": False,
                   "AutoSetupAdminAccounts": []}

        # TODO ManagedLocalUserShortName

        if dep_enrollment.use_realm_user:
            serialized_password_hash = None
            if self.realm_user.password_hash:
                serialized_password_hash = serialize_password_hash_dict(self.realm_user.password_hash)
            if not serialized_password_hash:
                # Auto populate form with realm user
                command["DontAutoPopulatePrimaryAccountInfo"] = False
                command["LockPrimaryAccountInfo"] = True
                command["PrimaryAccountFullName"] = self.realm_user.get_full_name()
                command["PrimaryAccountUserName"] = self.realm_user.device_username
                command["SetPrimarySetupAccountAsRegularUser"] = not dep_enrollment.realm_user_is_admin
            elif dep_enrollment.realm_user_is_admin:
                # Auto setup admin with realm user
                command["AutoSetupAdminAccounts"].append({
                    "fullName": self.realm_user.get_full_name(),
                    "shortName": self.realm_user.device_username,
                    "hidden": False,
                    "passwordHash": serialized_password_hash,
                })
                command["SkipPrimarySetupAccountCreation"] = True

        if dep_enrollment.has_hardcoded_admin():
            command["AutoSetupAdminAccounts"].append({
                "fullName": dep_enrollment.admin_full_name,
                "shortName": dep_enrollment.admin_short_name,
                "hidden": True,  # TODO => DEP Profile
                "passwordHash": serialize_password_hash_dict(dep_enrollment.admin_password_hash)
            })

        return command


register_command(AccountConfiguration)
