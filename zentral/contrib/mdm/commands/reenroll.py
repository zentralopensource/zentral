import logging
from zentral.contrib.mdm.models import Channel, ReEnrollmentSession
from zentral.contrib.mdm.payloads import build_mdm_configuration_profile
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.reenroll")


class Reenroll(Command):
    request_type = "InstallProfile"
    db_name = "Reenroll"

    @staticmethod
    def verify_channel_and_device(channel, enrolled_device):
        return channel == Channel.DEVICE

    def load_kwargs(self):
        self.reenrollment_session = None
        try:
            session_id = int(self.db_command.kwargs["session_id"])
        except Exception:
            raise ValueError(f"Command {self.uuid}: could not find session id")
        try:
            self.reenrollment_session = (
                ReEnrollmentSession.objects.select_related("enrolled_device",
                                                           "dep_enrollment__push_certificate",
                                                           "dep_enrollment__acme_issuer",
                                                           "dep_enrollment__scep_issuer",
                                                           "ota_enrollment__push_certificate",
                                                           "ota_enrollment__acme_issuer",
                                                           "ota_enrollment__scep_issuer",
                                                           "user_enrollment__push_certificate",
                                                           "user_enrollment__acme_issuer",
                                                           "user_enrollment__scep_issuer")
                                           .get(pk=session_id)
            )
        except ReEnrollmentSession.DoesNotExist:
            raise ValueError(f"Command {self.uuid}: could not find re-enrollment session {session_id}")

    def build_command(self):
        return {"Payload": build_mdm_configuration_profile(self.reenrollment_session)}

    @classmethod
    def create_for_enrollment_session(cls, enrollment_session):
        reenrollment_session = ReEnrollmentSession.objects.create_from_enrollment_session(enrollment_session)
        return cls.create_for_device(
            enrollment_session.enrolled_device,
            kwargs={"session_id": reenrollment_session.pk}
        )


register_command(Reenroll)
