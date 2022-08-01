import logging
from zentral.contrib.mdm.models import Channel, Platform, ReEnrollmentSession
from zentral.contrib.mdm.payloads import build_mdm_configuration_profile
from .base import register_command, Command


logger = logging.getLogger("zentral.contrib.mdm.commands.reenroll")


class Reenroll(Command):
    request_type = "InstallProfile"
    db_name = "Reenroll"
    allowed_channel = Channel.Device
    allowed_platform = (Platform.iOS, Platform.iPadOS, Platform.macOS, Platform.tvOS)
    allowed_in_user_enrollment = True

    def load_kwargs(self):
        self.reenrollment_session = None
        try:
            session_id = int(self.db_command.kwargs["session_id"])
        except Exception:
            logger.exception("Could not find session id")
            return
        try:
            self.reenrollment_session = (
                ReEnrollmentSession.objects.select_related("enrolled_device",
                                                           "dep_enrollment__push_certificate",
                                                           "dep_enrollment__scep_config",
                                                           "ota_enrollment__push_certificate",
                                                           "ota_enrollment__scep_config",
                                                           "user_enrollment__push_certificate",
                                                           "user_enrollment__scep_config")
                                           .get(pk=session_id)
            )
        except ReEnrollmentSession.DoesNotExist:
            logger.warning("Could not find re-enrollment session %s", session_id)

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
