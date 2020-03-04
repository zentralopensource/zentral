import logging
import plistlib
from cryptography.x509.oid import NameOID
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.cms import (verify_signed_payload,
                                     verify_apple_iphone_device_ca_issuer_openssl,
                                     verify_zentral_scep_ca_issuer_openssl)
from zentral.contrib.mdm.events import OTAEnrollmentRequestEvent
from zentral.contrib.mdm.exceptions import EnrollmentSessionStatusError
from zentral.contrib.mdm.models import OTAEnrollmentSession
from zentral.contrib.mdm.payloads import (build_configuration_profile_response,
                                          build_ota_scep_configuration_profile,
                                          build_mdm_configuration_profile)
from .base import PostEventMixin

logger = logging.getLogger('zentral.contrib.mdm.views.ota')


class OTAEnrollView(PostEventMixin, View):
    event_class = OTAEnrollmentRequestEvent

    def post(self, request, *args, **kwargs):
        # Verify payload signature, extract signed payload
        try:
            certificates, payload = verify_signed_payload(request.read())
        except ValueError:
            self.abort("posted data is not signed")

        # find out which CA signed the certificate used to sign the payload
        # if iPhone CA: phase 2
        # if SCEP CA: phase 3
        # if unknown: phase 2  # TODO: verify. seen with self signed cert in 10.13 beta in VMWare.
        for certificate_i_cn, certificate_bytes, signing_certificate in certificates:
            if verify_apple_iphone_device_ca_issuer_openssl(certificate_bytes):
                phase = 2
                break
            elif verify_zentral_scep_ca_issuer_openssl(certificate_bytes):
                phase = 3
                break
            else:
                self.post_event("warning", reason="unknown signing certificate issuer '{}'".format(certificate_i_cn))
                phase = 2

        payload = plistlib.loads(payload)
        self.serial_number = payload["SERIAL"]
        self.udid = payload["UDID"]

        if phase == 2:
            # Verify the challenge
            challenge = payload.get("CHALLENGE")
            if not challenge:
                self.abort("missing challenge", phase=phase)

            # Pre-authenticated session ?
            session_enrollment = kwargs.pop("session")
            if session_enrollment:
                # running off a realm user authenticated existing ota enrollment session
                try:
                    es_request = verify_enrollment_secret(
                        "ota_enrollment_session",
                        challenge,
                        self.user_agent, self.ip,
                        self.serial_number, self.udid
                    )
                except EnrollmentSecretVerificationFailed as e:
                    self.abort("secret verification failed: '{}'".format(e.err_msg), phase=phase)

                ota_enrollment_session = es_request.enrollment_secret.ota_enrollment_session

                # for PostEventMixin
                self.realm_user = ota_enrollment_session.realm_user

                # update the OTA enrollment session
                ota_enrollment_session.set_phase2_status(es_request, self.serial_number, self.udid, payload)

            else:
                # running off a simple ota enrollment
                try:
                    es_request = verify_enrollment_secret(
                        "ota_enrollment",
                        challenge,
                        self.user_agent, self.ip,
                        self.serial_number, self.udid
                    )
                except EnrollmentSecretVerificationFailed as e:
                    self.abort("secret verification failed: '{}'".format(e.err_msg), phase=phase)

                ota_enrollment = es_request.enrollment_secret.ota_enrollment
                if ota_enrollment.realm:
                    self.abort("cannot use ota enrollment secret on ota enrollment with realm", phase=phase)

                # Start an OTA enrollment session directly in phase 2
                ota_enrollment_session = OTAEnrollmentSession.objects.create_from_machine_info(
                    ota_enrollment,
                    self.serial_number, self.udid,
                    payload
                )

            configuration_profile = build_ota_scep_configuration_profile(ota_enrollment_session)
            configuration_profile_filename = "zentral_ota_scep"

        elif phase == 3:
            # get the serial number from the DN of the payload signing certificate
            serial_number = signing_certificate.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
            if self.serial_number != serial_number:
                self.abort("signing certificate DN serial number != payload serial number", phase=phase)

            # get the ota enrollment session from the DN of the payload signing certificate
            cn = signing_certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            _, ota_enrollment_session_secret = cn.split("$")
            try:
                ota_enrollment_session = (
                    OTAEnrollmentSession.objects
                    .select_for_update()
                    .select_related("ota_enrollment", "enrollment_secret__meta_business_unit")
                    .get(enrollment_secret__secret=ota_enrollment_session_secret)
                )
            except OTAEnrollmentSession.DoesNotExist:
                self.abort("could not find ota enrollment session from payload signing certificate", phase=phase)

            # for PostEventMixin
            self.realm_user = ota_enrollment_session.realm_user

            # verify and update ota enrollment session status
            try:
                ota_enrollment_session.set_phase3_status()
            except EnrollmentSessionStatusError:
                self.abort("ota enrollment session has wrong status", phase=phase)

            # verify DN mbu
            ota_enrollment_session_mbu = ota_enrollment_session.enrollment_secret.meta_business_unit
            o = signing_certificate.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0]
            if int(o.value.split("$")[-1]) != ota_enrollment_session_mbu.pk:
                self.abort("DN mbu doesn't match ota enrollment session mbu", phase=phase)

            # Get the MDM push certificate
            push_certificate = ota_enrollment_session_mbu.metabusinessunitpushcertificate.push_certificate

            configuration_profile = build_mdm_configuration_profile(ota_enrollment_session, push_certificate)
            configuration_profile_filename = "zentral_mdm"

        self.post_event("success", phase=phase)

        return build_configuration_profile_response(configuration_profile, configuration_profile_filename)
