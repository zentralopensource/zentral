import logging
import uuid
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME, login as auth_login
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import resolve_url
from django.template.response import TemplateResponse
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import FormView, View
from accounts.events import post_failed_verification_event
from accounts.forms import VerifyTOTPForm, VerifyWebAuthnForm, ZentralAuthenticationForm
from realms.models import Realm
from zentral.conf import settings as zentral_settings
from zentral.utils.http import user_agent_and_ip_address_from_request


logger = logging.getLogger("zentral.accounts.views.auth")


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request):
    """
    Displays the login form and handles the login action.
    """
    redirect_to = request.POST.get(REDIRECT_FIELD_NAME,
                                   request.GET.get(REDIRECT_FIELD_NAME, ''))

    form = realm = None

    if request.method == "POST":
        form = ZentralAuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()

            # Ensure the user-originating redirection url is safe.
            if not url_has_allowed_host_and_scheme(url=redirect_to,
                                                   allowed_hosts={request.get_host()},
                                                   require_https=request.is_secure()):
                redirect_to = resolve_url(settings.LOGIN_REDIRECT_URL)

            if user.has_verification_device:
                # Redirect to verification page
                token = signing.dumps({"auth_backend": user.backend,
                                       "redirect_to": redirect_to,
                                       "user_id": user.id},
                                      salt="zentral_verify_token",
                                      key=settings.SECRET_KEY)
                request.session["verification_token"] = token
                user_agent, _ = user_agent_and_ip_address_from_request(request)
                try:
                    verification_device = user.get_prioritized_verification_devices(user_agent)[0]
                except ValueError:
                    form.add_error(None, "No configured verification devices compatible with your current browser.")
                else:
                    return HttpResponseRedirect(verification_device.get_verification_url())
            else:
                # Okay, security check complete. Log the user in.
                auth_login(request, form.get_user())

                return HttpResponseRedirect(redirect_to)
    else:
        try:
            realm_pk = uuid.UUID(request.GET.get("realm"))
            realm = Realm.objects.get(enabled_for_login=True, pk=realm_pk)
        except (Realm.DoesNotExist, TypeError, ValueError):
            form = ZentralAuthenticationForm(request)

    context = {
        "redirect_to": redirect_to,
        "redirect_field_name": REDIRECT_FIELD_NAME,
    }
    if form:
        context["form"] = form
    if realm:
        login_realms = [realm]
    else:
        login_realms = Realm.objects.filter(enabled_for_login=True)
    context["login_realms"] = [(r, reverse("realms_public:login", args=(r.pk,)))
                               for r in login_realms]

    return TemplateResponse(request, "registration/login.html", context)


class BaseVerify2FView(FormView):
    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        request = self.request
        user_agent, _ = user_agent_and_ip_address_from_request(request)
        kwargs["session"] = request.session
        kwargs["user_agent"] = user_agent
        return kwargs

    def form_valid(self, form):
        self.request.session["mfa_authenticated"] = True
        auth_login(self.request, form.user)  # form.user has the backend (carried by the token from the login view)
        return HttpResponseRedirect(form.redirect_to)

    def form_invalid(self, form):
        post_failed_verification_event(self.request, form)
        return super().form_invalid(form)


class VerifyTOTPView(BaseVerify2FView):
    template_name = "accounts/verify_totp.html"
    form_class = VerifyTOTPForm


class VerifyWebAuthnView(BaseVerify2FView):
    template_name = "accounts/verify_webauthn.html"
    form_class = VerifyWebAuthnForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["webauthn_challenge"] = VerifyWebAuthnForm(session=self.request.session).set_challenge()
        return ctx


class NginxAuthRequestView(View):
    def get_external_link_authorization_groups(self):
        original_uri = self.request.META.get("HTTP_X_ORIGINAL_URI")
        if not original_uri:
            return
        original_uri_first_elem = original_uri.strip("/").split("/")[0]
        for link in zentral_settings.get('extra_links', []):
            authorized_groups = link.get("authorized_groups")
            if not authorized_groups:
                continue
            url = link.get("url")
            if not url:
                continue
            if url.startswith("http") or url.startswith("//"):
                continue
            url_first_elem = url.strip("/").split("/")[0]
            if url_first_elem == original_uri_first_elem:
                return authorized_groups

    def get(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            if (
                request.headers.get('x-requested-with') == 'XMLHttpRequest'
                or request.META.get('HTTP_ACCEPT', '').startswith('application/json')
            ):
                status_code = 403
            else:
                status_code = 401
            response = HttpResponse('Signed out')
            response.status_code = status_code
            return response
        else:
            if not request.user.is_superuser:
                authorized_groups = self.get_external_link_authorization_groups()
                if authorized_groups and not request.user.group_name_set.intersection(authorized_groups):
                    # no common groups
                    raise PermissionDenied("Not allowed")
            response = HttpResponse("OK")
            response["X-Zentral-Username"] = request.user.username
            response["X-Zentral-Email"] = request.user.email
            return response
