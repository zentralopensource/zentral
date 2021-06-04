import base64
import logging
import plistlib
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import View
from realms.models import RealmUser
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload
from zentral.contrib.mdm.events import DEPEnrollmentRequestEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession, DEPEnrollment
from zentral.contrib.mdm.payloads import build_configuration_profile_response, build_mdm_configuration_profile
from .base import PostEventMixin


logger = logging.getLogger('zentral.contrib.mdm.views.dep')


class DEPEnrollMixin(PostEventMixin):
    event_class = DEPEnrollmentRequestEvent

    def get_payload(self):
        # Verify payload signature, extract signed payload
        try:
            payload_data = verify_iphone_ca_signed_payload(self.get_payload_data())
        except ValueError:
            self.abort("Could not verify signer certificate")

        payload = plistlib.loads(payload_data)

        self.serial_number = payload["SERIAL"]
        self.udid = payload["UDID"]

        return payload

    def verify_dep_enrollment_secret(self):
        try:
            es_request = verify_enrollment_secret(
                "dep_enrollment",
                self.kwargs["dep_enrollment_secret"],
                self.user_agent, self.ip,
                self.serial_number, self.udid
            )
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            return es_request, es_request.enrollment_secret.dep_enrollment


class MDMProfileResponseMixin:
    def build_mdm_configuration_profile_response(self, dep_enrollment_session):
        configuration_profile = build_mdm_configuration_profile(
            dep_enrollment_session,
            dep_enrollment_session.dep_enrollment.push_certificate
        )
        configuration_profile_filename = "zentral_mdm"
        self.post_event("success", **dep_enrollment_session.serialize_for_event())
        return build_configuration_profile_response(configuration_profile, configuration_profile_filename)


class DEPEnrollView(DEPEnrollMixin, MDMProfileResponseMixin, View):
    def get_payload_data(self):
        return self.request.read()

    def post(self, request, *args, **kwargs):
        self.get_payload()
        es_request, dep_enrollment = self.verify_dep_enrollment_secret()
        if dep_enrollment.realm:
            # should never happen
            self.abort("this DEP enrollment requires an authenticated realm user")

        # Start a DEP enrollment session
        dep_enrollment_session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            dep_enrollment,
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
    return reverse("mdm:dep_enrollment_session", args=(dep_enrollment_session.enrollment_secret.secret,))


class DEPWebEnrollView(DEPEnrollMixin, View):
    # https://developer.apple.com/documentation/devicemanagement/device_assignment/authenticating_through_web_views

    def get_payload_data(self):
        try:
            return base64.b64decode(self.request.META["HTTP_X_APPLE_ASPEN_DEVICEINFO"])
        except KeyError:
            self.abort("Missing x-apple-aspen-deviceinfo header")

    def get(self, request, *args, **kwargs):
        payload = self.get_payload()
        es_request, dep_enrollment = self.verify_dep_enrollment_secret()
        if not dep_enrollment.realm:
            # should never happen
            self.abort("this DEP enrollment has no realm")

        # start realm auth session, do redirect
        callback = "zentral.contrib.mdm.views.dep.dep_web_enroll_callback"
        callback_kwargs = {"dep_enrollment_pk": dep_enrollment.pk,
                           "serial_number": self.serial_number,
                           "udid": self.udid,
                           "payload": payload}
        if dep_enrollment.use_realm_user and \
           dep_enrollment.realm_user_is_admin and \
           dep_enrollment.realm.backend_instance.can_get_password:
            callback_kwargs["save_password_hash"] = True

        return HttpResponseRedirect(
            dep_enrollment.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
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
