import logging
from uuid import uuid4
from django.db import transaction
from zentral.contrib.mdm.events import post_admin_password_updated_event
from zentral.contrib.mdm.models import Channel, DEPEnrollment, DEPEnrollmentSession, Platform
from zentral.contrib.mdm.payloads import substitute_variables
from zentral.core.secret_engines import decrypt_str, encrypt_str
from zentral.utils.passwords import build_password_hash_dict, serialize_password_hash_dict
from .base import register_command, Command
from .set_auto_admin_password import generate_password


logger = logging.getLogger("zentral.contrib.mdm.commands.account_configuration")


def get_secret_engine_kwargs(uuid):
    return {"model": "mdm.devicecommand", "field": "admin_password", "uuid": str(uuid)}


class AccountConfiguration(Command):
    request_type = "AccountConfiguration"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return (
            channel == Channel.DEVICE
            and enrolled_device.platform == Platform.MACOS
            and not enrolled_device.user_enrollment
        )

    @classmethod
    def create_for_target_and_dep_enrollment(cls, target, dep_enrollment):
        if not isinstance(dep_enrollment, DEPEnrollment):
            raise ValueError("Invalid enrollment")
        kwargs = None
        uuid = uuid4()
        if dep_enrollment.has_auto_admin():
            password = generate_password(complexity=dep_enrollment.admin_password_complexity)
            kwargs = {"admin_password": encrypt_str(password, **get_secret_engine_kwargs(uuid))}
        return super().create_for_target(target, kwargs=kwargs, uuid=uuid)

    def load_admin_password(self):
        encrypted_admin_password = self.db_command.kwargs.get("admin_password")
        if encrypted_admin_password:
            return decrypt_str(encrypted_admin_password, **get_secret_engine_kwargs(self.uuid))

    def build_command(self):
        if not isinstance(self.enrollment_session, DEPEnrollmentSession):
            raise ValueError("Invalid enrollment session")
        dep_enrollment = self.enrollment_session.dep_enrollment

        command = {"DontAutoPopulatePrimaryAccountInfo": True,
                   "SkipPrimarySetupAccountCreation": False,
                   "AutoSetupAdminAccounts": []}

        if dep_enrollment.use_realm_user:
            serialized_password_hash = None
            if self.realm_user.password_hash:
                serialized_password_hash = serialize_password_hash_dict(self.realm_user.password_hash)
            if not serialized_password_hash:
                # Auto populate form with realm user
                command["DontAutoPopulatePrimaryAccountInfo"] = False
                command["LockPrimaryAccountInfo"] = True
                command["PrimaryAccountFullName"] = self.realm_user.get_full_name()
                command["PrimaryAccountUserName"] = substitute_variables(dep_enrollment.username_pattern,
                                                                         self.enrollment_session)
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

        if dep_enrollment.has_auto_admin():
            command["AutoSetupAdminAccounts"].append({
                "fullName": dep_enrollment.admin_full_name,
                "shortName": dep_enrollment.admin_short_name,
                "hidden": dep_enrollment.hidden_admin,
                "passwordHash": serialize_password_hash_dict(
                    build_password_hash_dict(self.load_admin_password())
                ),
            })
            if not dep_enrollment.use_realm_user and dep_enrollment.auto_advance_setup:
                command["SkipPrimarySetupAccountCreation"] = True

        return command

    def command_acknowledged(self):
        admin_password = self.load_admin_password()
        if admin_password:
            self.enrolled_device.set_admin_password(admin_password)
            self.enrolled_device.save()
            transaction.on_commit(lambda: post_admin_password_updated_event(self))


register_command(AccountConfiguration)
