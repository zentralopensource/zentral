import base64
import logging
import plistlib
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import View
from realms.models import RealmUser
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload
from zentral.contrib.mdm.events import DEPEnrollmentRequestEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession, DEPEnrollment, EnrolledDevice
from zentral.contrib.mdm.payloads import build_configuration_profile_response, build_mdm_configuration_profile
from zentral.utils.os_version import make_comparable_os_version
from .base import PostEventMixin


logger = logging.getLogger('zentral.contrib.mdm.public_views.dep')


class DEPEnrollMixin(PostEventMixin):
    event_class = DEPEnrollmentRequestEvent

    def get_payload(self):
        # Verify payload signature, extract signed payload
        try:
            payload_data = verify_iphone_ca_signed_payload(self.get_payload_data())
        except ValueError:
            self.abort("Could not verify signer certificate")

        payload = plistlib.loads(payload_data)

        self.mdm_can_request_software_update = payload.get("MDM_CAN_REQUEST_SOFTWARE_UPDATE", False)
        self.os_version = " ".join(
            s for s in (
                payload.get(k) for k in ("OS_VERSION", "SUPPLEMENTAL_OS_VERSION_EXTRA")
            )
            if s
        )
        self.product = payload["PRODUCT"]
        self.serial_number = payload["SERIAL"]
        self.udid = payload["UDID"]

        return payload

    def verify_blocked_device(self):
        if EnrolledDevice.objects.blocked().filter(serial_number=self.serial_number).exists():
            self.abort("Device blocked")

    def verify_enrollment_secret(self):
        try:
            self.es_request = verify_enrollment_secret(
                "dep_enrollment",
                self.kwargs["dep_enrollment_secret"],
                self.user_agent, self.ip,
                self.serial_number, self.udid
            )
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            self.dep_enrollment = self.es_request.enrollment_secret.dep_enrollment

    def verify_os_version(self):
        # see https://github.com/apple/device-management/blob/b838baacf2e790db729b6ca3f52724adc8bfb96d/mdm/errors/softwareupdate.required.yaml  # NOQA
        if not self.mdm_can_request_software_update:
            # NOOP
            return
        if "iPhone" in self.product or "iPad" in self.product:
            platform = "ios"
        elif "Mac" in self.product:
            platform = "macos"
        else:
            logger.error("Unknown product for required software update: %s", self.product)
            return
        required_os_version = getattr(self.dep_enrollment, f"{platform}_min_version")
        comparable_required_os_version = make_comparable_os_version(required_os_version)
        comparable_os_version = make_comparable_os_version(self.os_version)
        if comparable_required_os_version > comparable_os_version:
            self.post_event("warning", reason=f"OS update to version {required_os_version} required")
            return JsonResponse({
                "code": "com.apple.softwareupdate.required",
                "details": {"OSVersion": required_os_version}
            }, status=403)

    def verify(self):
        self.verify_blocked_device()
        self.verify_enrollment_secret()
        err_response = self.verify_os_version()
        return err_response


class MDMProfileResponseMixin:
    def build_mdm_configuration_profile_response(self, dep_enrollment_session):
        configuration_profile = build_mdm_configuration_profile(dep_enrollment_session)
        configuration_profile_filename = "zentral_mdm"
        self.post_event("success", **dep_enrollment_session.serialize_for_event())
        return build_configuration_profile_response(configuration_profile, configuration_profile_filename)


class DEPEnrollView(DEPEnrollMixin, MDMProfileResponseMixin, View):
    def get_payload_data(self):
        return self.request.read()

    def post(self, request, *args, **kwargs):
        self.get_payload()
        err_response = self.verify()
        if err_response:
            return err_response
        if self.dep_enrollment.realm:
            # should never happen
            self.abort("this DEP enrollment requires an authenticated realm user")

        # Start a DEP enrollment session
        dep_enrollment_session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            self.dep_enrollment,
            self.serial_number, self.udid,
        )
        return self.build_mdm_configuration_profile_response(dep_enrollment_session)


def realm_user_session_key(dep_enrollment_session):
    return "_dep_enrollment_session_{}_realm_user_pk".format(dep_enrollment_session.pk)


def dep_web_enroll_callback(request, realm_authentication_session, dep_enrollment_pk, serial_number, udid, payload):
    dep_enrollment = DEPEnrollment.objects.get(pk=dep_enrollment_pk, realm__isnull=False)

    realm_user = realm_authentication_session.user

    # Start a DEP enrollment session
    dep_enrollment_session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
        dep_enrollment,
        serial_number, udid,
        commit=False
    )
    dep_enrollment_session.realm_user = realm_user
    dep_enrollment_session.save()

    # add user to session
    request.session[realm_user_session_key(dep_enrollment_session)] = str(realm_user.pk)
    return reverse("mdm_public:dep_enrollment_session", args=(dep_enrollment_session.enrollment_secret.secret,))


class DEPWebEnrollView(DEPEnrollMixin, View):
    # https://developer.apple.com/documentation/devicemanagement/device_assignment/authenticating_through_web_views

    def get_payload_data(self):
        try:
            return base64.b64decode(self.request.META["HTTP_X_APPLE_ASPEN_DEVICEINFO"])
        except KeyError:
            self.abort("Missing x-apple-aspen-deviceinfo header")

    def get(self, request, *args, **kwargs):
        payload = self.get_payload()
        err_response = self.verify()
        if err_response:
            return err_response
        if not self.dep_enrollment.realm:
            # should never happen
            self.abort("this DEP enrollment has no realm")

        # start realm auth session, do redirect
        callback = "zentral.contrib.mdm.public_views.dep.dep_web_enroll_callback"
        callback_kwargs = {"dep_enrollment_pk": self.dep_enrollment.pk,
                           "serial_number": self.serial_number,
                           "udid": self.udid,
                           "payload": payload}
        if self.dep_enrollment.use_realm_user and \
           self.dep_enrollment.realm_user_is_admin and \
           self.dep_enrollment.realm.backend_instance.can_get_password:
            callback_kwargs["save_password_hash"] = True

        return HttpResponseRedirect(
            self.dep_enrollment.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
        )


class DEPEnrollmentSessionView(PostEventMixin, MDMProfileResponseMixin, View):
    event_class = DEPEnrollmentRequestEvent

    def get(self, request, *args, **kwargs):
        dep_enrollment_session = get_object_or_404(
            DEPEnrollmentSession,
            enrollment_secret__secret=kwargs["dep_enrollment_session_secret"],
            dep_enrollment__realm__isnull=False
        )

        # for PostEventMixin
        enrollment_secret = dep_enrollment_session.enrollment_secret
        self.serial_number = enrollment_secret.serial_numbers[0]
        self.udid = enrollment_secret.serial_numbers[0]

        # check the auth
        try:
            realm_user_pk = self.request.session.pop(realm_user_session_key(dep_enrollment_session))
            self.realm_user = RealmUser.objects.get(realm=dep_enrollment_session.dep_enrollment.realm,
                                                    pk=realm_user_pk)
        except (KeyError, RealmUser.DoesNotExist):
            # should not happen
            self.abort("DEP enrollment session - request not authenticated")
        if self.realm_user != dep_enrollment_session.realm_user:
            # should not happen
            self.abort("DEP enrollment session - realm user missmatch")

        return self.build_mdm_configuration_profile_response(dep_enrollment_session)
