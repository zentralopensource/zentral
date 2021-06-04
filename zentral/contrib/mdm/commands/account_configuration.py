import base64
import copy
import logging
import plistlib
from zentral.contrib.mdm.models import Channel, Platform, DEPEnrollmentSession
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.account_configuration")


class AccountConfiguration(Command):
    request_type = "AccountConfiguration"
    allowed_channel = Channel.Device
    allowed_platform = Platform.macOS
    allowed_in_user_enrollment = False

    def _serialize_realm_user_password_hash(self):
        password_hash = self.realm_user.password_hash
        if not password_hash:
            return
        password_hash = copy.deepcopy(password_hash)
        for hash_type, hash_dict in password_hash.items():
            for k, v in hash_dict.items():
                if isinstance(v, str):
                    # decode base64 encoded bytes
                    hash_dict[k] = base64.b64decode(v.encode("utf-8"))  # => bytes to get <data/> in the plist
        return plistlib.dumps(password_hash).strip()

    def build_command(self):
        if not isinstance(self.enrollment_session, DEPEnrollmentSession):
            raise ValueError("Invalid enrollment session")
        dep_enrollment = self.enrollment_session.dep_enrollment

        command = {"DontAutoPopulatePrimaryAccountInfo": True,
                   "AutoSetupAdminAccounts": []}

        # TODO upgrade
        # - when an extra admin is set in enrollment and the primary user is admin
        # - use ManagedLocalUserShortName

        # auto populate primary account
        if dep_enrollment.use_realm_user and dep_enrollment.realm_user_is_admin:
            serialized_password_hash = self._serialize_realm_user_password_hash()
            if not serialized_password_hash:
                # Auto populate
                command["DontAutoPopulatePrimaryAccountInfo"] = False
                command["PrimaryAccountFullName"] = self.realm_user.get_full_name()
                command["PrimaryAccountUserName"] = self.realm_user.device_username
                command["SetPrimarySetupAccountAsRegularUser"] = False
            else:
                # Auto setup admin
                admin_account = {"fullName": self.realm_user.get_full_name(),
                                 "shortName": self.realm_user.device_username,
                                 "hidden": False,  # TODO => DEP Profile
                                 "passwordHash": serialized_password_hash}
                command["AutoSetupAdminAccounts"].append(admin_account)

        auto_populate = command.get("DontAutoPopulatePrimaryAccountInfo") is False

        command["LockPrimaryAccountInfo"] = auto_populate
        command["SkipPrimarySetupAccountCreation"] = not auto_populate
        return command


register_command(AccountConfiguration)
