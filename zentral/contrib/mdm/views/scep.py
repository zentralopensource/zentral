import logging
from zentral.contrib.mdm.events import MDMSCEPVerificationEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession, OTAEnrollmentSession
from zentral.utils.api_views import BaseVerifySCEPCSRView


logger = logging.getLogger('zentral.contrib.mdm.views.scep')


# SCEP verification


class VerifySCEPCSRView(BaseVerifySCEPCSRView):
    event_class = MDMSCEPVerificationEvent

    def get_enrollment_session_info(self, cn_prefix):
        # CN prefix => OTA enrollment phase
        if cn_prefix == "OTA" or cn_prefix == "MDM$OTA":
            model = "ota_enrollment_session"
            if cn_prefix == "OTA":
                return model, OTAEnrollmentSession.PHASE_2, "set_phase2_scep_verified_status"
            else:
                return model, OTAEnrollmentSession.PHASE_3, "set_phase3_scep_verified_status"
        elif cn_prefix == "MDM$DEP":
            return "dep_enrollment_session", DEPEnrollmentSession.STARTED, "set_scep_verified_status"
        else:
            self.abort("Unknown CN prefix {}".format(cn_prefix))
