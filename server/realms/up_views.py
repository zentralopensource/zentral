import logging
from django.middleware.csrf import rotate_token
from django.shortcuts import get_object_or_404, redirect
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import TemplateView
from .middlewares import SESSION_KEY
from .models import Realm


logger = logging.getLogger("zentral.realms.up_views")


def login_callback(request, realm_authentication_session, next_url=None):
    assert realm_authentication_session.realm.user_portal, "user portal not active in this realm"

    # test session
    req_ras = getattr(request, "realm_authentication_session", None)
    if req_ras:
        if req_ras.user != realm_authentication_session.user:
            # avoid reusing another user's session.
            request.session.flush()
    else:
        request.session.cycle_key()

    # add realm authentication session to session
    request.session[SESSION_KEY] = str(realm_authentication_session.pk)

    # set session expiry
    request.session.set_expiry(realm_authentication_session.computed_expiry())

    # rotate CSRF token
    rotate_token(request)

    return next_url or reverse("realms_public:up_index", args=(realm_authentication_session.realm.pk,))


class UPLoginRequiredMixin:
    def get_realm_user(self, request):
        self.realm_user = None
        realm_user = request.realm_authentication_session.user
        if not realm_user:
            logger.debug("No realm user found")
            return
        if realm_user.realm != self.realm:
            logger.debug("Existing realm authentication session on wrong realm")
            return
        if realm_user.scim_external_id and not realm_user.scim_active:
            logger.error("Inactive realm user %s", realm_user)
            return
        self.realm_user = realm_user

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["realm_pk"], user_portal=True)
        self.get_realm_user(request)
        if not self.realm_user:
            # redirect to login
            callback = "realms.up_views.login_callback"
            callback_kwargs = {}
            next_url = request.build_absolute_uri()
            if next_url and url_has_allowed_host_and_scheme(url=next_url,
                                                            allowed_hosts={request.get_host()},
                                                            require_https=True):
                callback_kwargs["next_url"] = next_url
            redirect_url = self.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
            if redirect_url:
                return redirect(redirect_url)
            else:
                # should never happen
                raise ValueError(f"Empty realm {self.realm.pk} redirect URL")
        return super().dispatch(request, *args, **kwargs)


class UPTemplateView(UPLoginRequiredMixin, TemplateView):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        ctx["realm_user"] = self.realm_user
        return ctx


class IndexView(UPTemplateView):
    template_name = "user_portal/index.html"


class LogoutView(TemplateView):
    template_name = "user_portal/logout.html"
    http_method_names = ["post", "options"]

    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["realm_pk"], user_portal=True)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        request.session.flush()
        if hasattr(request, "realm_authentication_session"):
            request.realm_authentication_session = None
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["realm"] = self.realm
        ctx["login_url"] = self.realm.backend_instance.initialize_session(
            self.request, "realms.up_views.login_callback"
        )
        return ctx
