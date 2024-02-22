import logging
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.views.generic import View
from zentral.conf import settings
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.contrib.mdm.events import UserEnrollmentRequestEvent
from zentral.contrib.mdm.models import UserEnrollment, UserEnrollmentSession
from zentral.contrib.mdm.payloads import build_configuration_profile_response, build_mdm_configuration_profile
from .base import PostEventMixin


logger = logging.getLogger('zentral.contrib.mdm.public_views.user')


class UserEnrollmentServiceDiscoveryView(View):
    def get(self, request, *args, **kwargs):
        user_enrollment = get_object_or_404(
            UserEnrollment,
            enrollment_secret__secret=kwargs["secret"]
        )
        return JsonResponse({
            "Servers": [
                {"Version": "mdm-byod",
                 "BaseURL": "https://{}{}".format(
                     settings["api"]["fqdn"],
                     reverse("mdm_public:enroll_user", args=(user_enrollment.enrollment_secret.secret,)))}
            ]
        })


class EnrollUserView(PostEventMixin, View):
    event_class = UserEnrollmentRequestEvent

    def verify_enrollment_secret(self):
        try:
            es_request = verify_enrollment_secret(
                "user_enrollment",
                self.kwargs["secret"],
                self.user_agent, self.ip
            )
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            self.user_enrollment = es_request.enrollment_secret.user_enrollment
            if not self.user_enrollment.realm:  # Deprecated, should never happen
                self.abort("This user enrollment has no realm")

    def post(self, request, *args, **kwargs):
        self.verify_enrollment_secret()
        authorization = request.headers.get("Authorization")
        if not authorization:
            user_enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(self.user_enrollment)
            url = "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm_public:authenticate_user", args=(user_enrollment_session.enrollment_secret.secret,))
            )
            response = HttpResponse("Unauthorized", status=401)
            response["WWW-Authenticate"] = f'Bearer method="apple-as-web" url="{url}"'
            self.post_event("success", **user_enrollment_session.serialize_for_event())
            return response
        else:
            access_token = authorization.replace("Bearer", "").strip()
            try:
                user_enrollment_session = UserEnrollmentSession.objects.get(
                    user_enrollment=self.user_enrollment,
                    access_token=access_token
                )
            except UserEnrollmentSession.DoesNotExist:
                self.abort("Invalid access token")
            user_enrollment_session.set_started_status()
            configuration_profile = build_mdm_configuration_profile(user_enrollment_session)
            configuration_profile_filename = "zentral_mdm"
            self.post_event("success", **user_enrollment_session.serialize_for_event())
            return build_configuration_profile_response(configuration_profile, configuration_profile_filename)


def user_enroll_callback(request, realm_authentication_session, user_enrollment_session_pk):
    user_enrollment_session = UserEnrollmentSession.objects.get(
        pk=user_enrollment_session_pk,
        user_enrollment__realm=realm_authentication_session.realm
    )
    user_enrollment_session.set_account_driven_authenticated_status(realm_authentication_session.user)
    scheme = "apple-remotemanagement-user-login"
    if scheme not in HttpResponseRedirect.allowed_schemes:
        HttpResponseRedirect.allowed_schemes.append(scheme)
    return HttpResponseRedirect(
        f"{scheme}://authentication-results?access-token={user_enrollment_session.access_token}",
        status=308
    )


class AuthenticateUserView(PostEventMixin, View):
    event_class = UserEnrollmentRequestEvent

    def verify_enrollment_secret(self):
        try:
            es_request = verify_enrollment_secret(
                "user_enrollment_session",
                self.kwargs["secret"],
                self.user_agent, self.ip
            )
        except EnrollmentSecretVerificationFailed as e:
            self.abort("secret verification failed: '{}'".format(e.err_msg))
        else:
            self.user_enrollment_session = es_request.enrollment_secret.user_enrollment_session
            self.realm = self.user_enrollment_session.user_enrollment.realm
            if not self.realm:  # Deprecated, should never happen
                self.abort("This user enrollment has no realm")

    def get(self, request, *args, **kwargs):
        self.verify_enrollment_secret()
        # start realm auth session, do redirect
        callback = "zentral.contrib.mdm.public_views.user.user_enroll_callback"
        callback_kwargs = {"user_enrollment_session_pk": self.user_enrollment_session.pk}
        return HttpResponseRedirect(
            self.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
        )
