import logging
import plistlib
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.cms import (sign_payload_openssl,
                                     verify_signed_payload,
                                     verify_apple_iphone_device_ca_issuer_openssl)
from zentral.contrib.mdm.events import DEPEnrollmentRequestEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession
from zentral.contrib.mdm.payloads import build_payload_response, build_mdm_payload
from .base import PostEventMixin

logger = logging.getLogger('zentral.contrib.mdm.views.dep')


class DEPEnrollView(PostEventMixin, View):
    event_class = DEPEnrollmentRequestEvent

    def post(self, request, *args, **kwargs):
        # Verify payload signature, extract signed payload
        try:
            certificates, payload = verify_signed_payload(request.read())
        except ValueError as error:
            self.abort("posted data is not signed", signature_error=str(error))

        for certificate_i_cn, certificate_bytes, signing_certificate in certificates:
            if verify_apple_iphone_device_ca_issuer_openssl(certificate_bytes):
                break

        payload = plistlib.loads(payload)
        self.serial_number = payload["SERIAL"]
        self.udid = payload["UDID"]

        try:
            es_request = verify_enrollment_secret(
                "dep_profile",
                self.kwargs["dep_profile_secret"],
                self.user_agent, self.ip,
                self.serial_number, self.udid
            )
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))

        # Start a DEP enrollment session
        dep_enrollment_session = DEPEnrollmentSession.objects.create_from_dep_profile(
            es_request.enrollment_secret.dep_profile,
            self.serial_number, self.udid,
            payload
        )

        # Get the MDM push certificate
        push_certificate = (dep_enrollment_session.enrollment_secret
                                                  .meta_business_unit
                                                  .metabusinessunitpushcertificate
                                                  .push_certificate)

        payload = build_mdm_payload(dep_enrollment_session, push_certificate)
        filename = "zentral_mdm"
        self.post_event("success", **dep_enrollment_session.serialize_for_event())
        return build_payload_response(sign_payload_openssl(payload), filename)
