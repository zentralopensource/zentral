import base64
import logging
from asn1crypto import csr
from django.core.exceptions import SuspiciousOperation
from django.shortcuts import get_object_or_404
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.events import MDMSCEPVerificationEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession, OTAEnrollmentSession
from zentral.utils.api_views import SignedRequestHeaderJSONPostAPIView


logger = logging.getLogger('zentral.contrib.mdm.views.scep')


# SCEP verification


class VerifySCEPCSRView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral"
    event_class = MDMSCEPVerificationEvent
    serial_number = None

    def post_event(self, status, **event_payload):
        event_payload["status"] = status
        self.event_class.post_machine_request_payloads(self.serial_number, self.user_agent, self.ip,
                                                       [event_payload])

    def abort(self, reason, **event_payload):
        if reason:
            event_payload["reason"] = reason
        self.post_event("failure", **event_payload)
        raise SuspiciousOperation(reason)

    def do_post(self, data):
        csr_data = base64.b64decode(data["csr"].encode("ascii"))
        csr_info = csr.CertificationRequest.load(csr_data)["certification_request_info"]

        csr_d = {}

        # subject
        for rdn_idx, rdn in enumerate(csr_info["subject"].chosen):
            for type_val_idx, type_val in enumerate(rdn):
                csr_d[type_val["type"].native] = type_val['value'].native

        kwargs = {"user_agent": self.user_agent,
                  "public_ip_address": self.ip}

        # serial number
        self.serial_number = csr_d.get("serial_number")
        if not self.serial_number:
            self.abort("Could not get serial number")
        kwargs["serial_number"] = self.serial_number

        # meta business
        organization_name = csr_d.get("organization_name")
        if not organization_name or not organization_name.startswith("MBU$"):
            self.abort("Unknown organization name format")
        meta_business_unit_id = int(organization_name.split("$", 1)[-1])
        kwargs["meta_business_unit"] = get_object_or_404(MetaBusinessUnit, pk=meta_business_unit_id)

        # type and session secret
        try:
            cn_prefix, kwargs["secret"] = csr_d["common_name"].rsplit("$", 1)
        except (KeyError, ValueError, AttributeError):
            self.abort("Unknown common name format")

        # CN prefix => OTA enrollment phase
        if cn_prefix == "OTA" or cn_prefix == "MDM$OTA":
            kwargs["model"] = "ota_enrollment_session"
            if cn_prefix == "OTA":
                kwargs["ota_enrollment_session__status"] = OTAEnrollmentSession.PHASE_2
                update_status_method = "set_phase2_scep_verified_status"
            else:
                kwargs["ota_enrollment_session__status"] = OTAEnrollmentSession.PHASE_3
                update_status_method = "set_phase3_scep_verified_status"
        elif cn_prefix == "MDM$DEP":
            kwargs["model"] = "dep_enrollment_session"
            kwargs["dep_enrollment_session__status"] = DEPEnrollmentSession.STARTED
            update_status_method = "set_scep_verified_status"
        else:
            self.abort("Unknown CN prefix {}".format(cn_prefix))

        try:
            es_request = verify_enrollment_secret(**kwargs)
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            # update the enrollment session status
            enrollment_session = getattr(es_request.enrollment_secret, kwargs["model"])
            getattr(enrollment_session, update_status_method)(es_request)
            self.post_event("success", **enrollment_session.serialize_for_event())

        # OK
        return {"status": 0}
