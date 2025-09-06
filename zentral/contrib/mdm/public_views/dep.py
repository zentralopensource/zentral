import base64
import logging
import plistlib
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.template import Context, Engine
from django.urls import reverse
from django.views.generic import View
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.crypto import verify_iphone_ca_signed_payload
from zentral.contrib.mdm.events import DEPEnrollmentRequestEvent
from zentral.contrib.mdm.models import DEPEnrollmentSession, DEPEnrollment, EnrolledDevice
from zentral.contrib.mdm.payloads import build_configuration_profile_response, build_mdm_configuration_profile
from zentral.contrib.mdm.software_updates import best_available_software_update_for_device_id_and_build
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
            self.abort("could not verify payload signer certificate")

        self.payload = plistlib.loads(payload_data)

        self.mdm_can_request_software_update = self.payload.get("MDM_CAN_REQUEST_SOFTWARE_UPDATE", False)
        self.os_version = " ".join(
            s for s in (
                self.payload.get(k) for k in ("OS_VERSION", "SUPPLEMENTAL_OS_VERSION_EXTRA")
            )
            if s
        )
        self.software_update_device_id = self.payload.get("SOFTWARE_UPDATE_DEVICE_ID")
        self.build = self.payload.get("SUPPLEMENTAL_BUILD_VERSION") or self.payload.get("VERSION")
        self.product = self.payload["PRODUCT"]
        self.serial_number = self.payload["SERIAL"]
        self.udid = self.payload["UDID"]

        return self.payload

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
        # max OS version
        details = None
        required_max_os_version = getattr(self.dep_enrollment, f"{platform}_max_version")
        if required_max_os_version and self.software_update_device_id and self.build:
            software_update = best_available_software_update_for_device_id_and_build(
                self.software_update_device_id, self.build
            )
            if software_update and software_update.comparable_os_version > make_comparable_os_version(self.os_version):
                details = {"OSVersion": software_update.target_os_version()}
                if software_update.build:
                    details["BuildVersion"] = software_update.build
        if not details:
            # min OS version
            required_min_os_version = getattr(self.dep_enrollment, f"{platform}_min_version")
            if required_min_os_version:
                comparable_required_min_os_version = make_comparable_os_version(required_min_os_version)
                comparable_os_version = make_comparable_os_version(self.os_version)
                if comparable_required_min_os_version > comparable_os_version:
                    details = {"OSVersion": required_min_os_version}
        if details:
            self.post_event("warning", reason=f"OS update to version {details['OSVersion']} required")
            return JsonResponse({
                "code": "com.apple.softwareupdate.required",
                "details": details,
            }, status=403)

    def verify(self):
        self.verify_blocked_device()
        self.verify_enrollment_secret()
        err_response = self.verify_os_version()
        return err_response


class MDMProfileResponseMixin:
    def build_mdm_configuration_profile_response(self, dep_enrollment_session):
        configuration_profile = build_mdm_configuration_profile(
            dep_enrollment_session,
            machine_info=self.payload
        )
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


# DEP web enroll views


def get_dep_web_enroll_next_custom_view(dep_enrollment, authenticated, current_decv):
    select_next = current_decv is None
    for decv in (
        dep_enrollment.depenrollmentcustomview_set
                      .select_related("custom_view")
                      .filter(custom_view__requires_authentication=authenticated)
                      .order_by("weight")
    ):
        if select_next:
            return decv
        elif decv == current_decv:
            select_next = True


DEP_ENROLLMENT_PAYLOAD_KEY = "_dep_web_enroll_payload"
DEP_ENROLLMENT_SESSION_KEY = "_dep_web_enroll_session_pk"


def get_dep_web_enroll_authentication_url(request, dep_enrollment):
    payload = request.session[DEP_ENROLLMENT_PAYLOAD_KEY]
    callback = "zentral.contrib.mdm.public_views.dep.dep_web_enroll_callback"
    callback_kwargs = {"dep_enrollment_pk": dep_enrollment.pk,
                       "serial_number": payload["SERIAL"],
                       "udid": payload["UDID"],
                       "payload": payload}
    if dep_enrollment.use_realm_user and \
       dep_enrollment.realm_user_is_admin and \
       dep_enrollment.realm.backend_instance.can_get_password:
        callback_kwargs["save_password_hash"] = True

    return dep_enrollment.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)


def get_dep_web_enroll_next_url(request, dep_enrollment, authenticated=False, current_decv=None):
    decv = get_dep_web_enroll_next_custom_view(dep_enrollment, authenticated, current_decv)
    if decv:
        # redirect to next custom view
        return reverse(
            "mdm_public:dep_web_enroll_custom_view",
            args=(dep_enrollment.enrollment_secret.secret, decv.pk)
        )
    if not authenticated:
        # redirect to authentication
        return get_dep_web_enroll_authentication_url(request, dep_enrollment)
    # By default, redirect to MDM profile
    return reverse("mdm_public:dep_web_enroll_profile", args=(dep_enrollment.enrollment_secret.secret,))


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

    # update session
    request.session[DEP_ENROLLMENT_PAYLOAD_KEY] = payload
    request.session[DEP_ENROLLMENT_SESSION_KEY] = dep_enrollment_session.pk

    # next page
    return get_dep_web_enroll_next_url(request, dep_enrollment, authenticated=True, current_decv=None)


class DEPWebEnrollView(DEPEnrollMixin, View):
    # https://developer.apple.com/documentation/devicemanagement/device_assignment/authenticating_through_web_views

    def get_payload_data(self):
        try:
            return base64.b64decode(self.request.META["HTTP_X_APPLE_ASPEN_DEVICEINFO"])
        except KeyError:
            self.abort("Missing x-apple-aspen-deviceinfo header")

    def get(self, request, *args, **kwargs):
        self.get_payload()
        err_response = self.verify()
        if err_response:
            return err_response
        if not self.dep_enrollment.realm:
            # should never happen
            self.abort("this DEP enrollment has no realm")

        # save payload
        request.session[DEP_ENROLLMENT_PAYLOAD_KEY] = self.payload

        # redirect to next view
        return HttpResponseRedirect(
            get_dep_web_enroll_next_url(request, self.dep_enrollment, authenticated=False, current_decv=None)
        )


class DEPWebEnrollCustomView(PostEventMixin, View):
    event_class = DEPEnrollmentRequestEvent

    def get_next_url(self, request):
        return get_dep_web_enroll_next_url(request, self.dep_enrollment, self.authenticated, self.current_decv)

    def dispatch(self, request, *args, **kwargs):
        # PostEventMixin
        self.setup_with_request(request)

        self.dep_enrollment = get_object_or_404(
            DEPEnrollment,
            enrollment_secret__secret=kwargs["dep_enrollment_secret"]
        )
        self.payload = request.session[DEP_ENROLLMENT_PAYLOAD_KEY]
        self.serial_number = self.payload["SERIAL"]
        self.udid = self.payload["UDID"]
        self.current_decv = (
            self.dep_enrollment.depenrollmentcustomview_set.select_related("custom_view")
                                                           .filter(pk=kwargs["pk"])
                                                           .first()
        )
        self.realm_user = None
        try:
            self.realm_user = DEPEnrollmentSession.objects.get(
                dep_enrollment=self.dep_enrollment,
                pk=request.session[DEP_ENROLLMENT_SESSION_KEY]
            ).realm_user
        except KeyError:
            pass
        except DEPEnrollmentSession.DoesNotExist:
            logger.error("Unknown DEP enrollment session %s", request.session[DEP_ENROLLMENT_SESSION_KEY])
            del request.session[DEP_ENROLLMENT_SESSION_KEY]
        self.authenticated = self.realm_user is not None
        if not self.current_decv or self.current_decv.custom_view.requires_authentication != self.authenticated:
            # custom view not found probably because the configuration has changed, or auth not OK, we retry
            return HttpResponseRedirect(self.get_next_url(request))
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        ctx = {
            "payload_language": self.payload.get("LANGUAGE", "").replace("_", "-"),
            "request_language": request.META.get('HTTP_ACCEPT_LANGUAGE', "").split(",")[0],
            "authenticated": self.authenticated,
            "realm_user": self.realm_user,
            "serial_number": self.serial_number,
        }
        template_engine = Engine.get_default()
        template = template_engine.from_string(self.current_decv.custom_view.html)
        return HttpResponse(template.render(Context(ctx)), content_type="text/html")

    def post(self, request, *args, **kwargs):
        payload = {"custom_view": self.current_decv.custom_view.serialize_for_event(keys_only=True)}
        self.post_event("success", **payload)
        return HttpResponseRedirect(self.get_next_url(request))


class DEPWebEnrollProfileView(PostEventMixin, MDMProfileResponseMixin, View):
    event_class = DEPEnrollmentRequestEvent

    def get(self, request, *args, **kwargs):
        dep_enrollment_session = get_object_or_404(
            DEPEnrollmentSession,
            pk=request.session[DEP_ENROLLMENT_SESSION_KEY],
            realm_user__isnull=False,
            dep_enrollment__enrollment_secret__secret=kwargs["dep_enrollment_secret"],
            dep_enrollment__realm__isnull=False,
        )
        self.payload = request.session[DEP_ENROLLMENT_PAYLOAD_KEY]

        # for PostEventMixin
        enrollment_secret = dep_enrollment_session.enrollment_secret
        self.serial_number = enrollment_secret.serial_numbers[0]
        self.udid = enrollment_secret.udids[0]

        return self.build_mdm_configuration_profile_response(dep_enrollment_session)
