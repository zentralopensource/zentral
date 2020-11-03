import logging
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.http import is_safe_url
from django.views.generic import CreateView, DetailView, ListView, UpdateView, View
from .backends import backend_classes
from .exceptions import RealmUserError
from .models import Realm, RealmAuthenticationSession


logger = logging.getLogger("zentral.realms.views")


class CanManageRealmsMixin:
    """Authenticated local user with required permissions."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(self.request.get_full_path(),
                                     settings.LOGIN_URL,
                                     REDIRECT_FIELD_NAME)
        if request.user.is_remote:
            raise PermissionDenied("Remote users cannot access the realms settings")
        if request.session.get("_realm_authentication_session"):
            raise PermissionDenied("Log in without using a realm to access the realms settings")
        if not self.request.user.has_perms(('accounts.add_user', 'accounts.change_user', 'accounts.delete_user')):
            raise PermissionDenied("You do not have the required permissions to manage the realms.")
        return super().dispatch(request, *args, **kwargs)


class RealmListView(LoginRequiredMixin, ListView):
    model = Realm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["setup"] = True
        ctx["realms_count"] = ctx["object_list"].count()
        ctx["create_links"] = [
            {"url": reverse("realms:create", args=(slug,)),
             "anchor_text": backend_class.name}
            for slug, backend_class in backend_classes.items()
        ]
        ctx["can_manage_realms"] = (
            not self.request.user.is_remote
            and not self.request.session.get("_realm_authentication_session")
            and self.request.user.has_perms(('accounts.add_user', 'accounts.change_user', 'accounts.delete_user'))
        )
        return ctx


class CreateRealmView(CanManageRealmsMixin, CreateView):
    template_name = "realms/realm_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.backend = kwargs.pop("backend")
        if self.backend not in backend_classes:
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_form_class(self):
        return backend_classes.get(self.backend).get_form_class()

    def form_valid(self, form):
        self.object = form.save(commit=False)
        self.object.backend = self.backend
        self.object.save()
        return redirect(self.object)


class RealmView(CanManageRealmsMixin, DetailView):
    model = Realm


class UpdateRealmView(CanManageRealmsMixin, UpdateView):
    model = Realm
    fields = ("name",)

    def get_form_class(self):
        return self.object.backend_instance.get_form_class()


class LoginView(View):
    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"], enabled_for_login=True)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        callback = "realms.utils.login_callback"
        callback_kwargs = {}
        if request.method == "POST":
            next_url = request.POST.get(REDIRECT_FIELD_NAME)
            if next_url and is_safe_url(url=next_url,
                                        allowed_hosts={request.get_host()},
                                        require_https=request.is_secure()):
                callback_kwargs["next_url"] = next_url
        redirect_url = self.realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
        if redirect_url:
            return HttpResponseRedirect(redirect_url)
        else:
            raise ValueError("Empty realm {} redirect URL".format(self.realm.pk))

    def get(self, request, *args, **kwargs):
        redirect_url = "{}?realm={}".format(reverse("login"), self.realm.pk)
        return HttpResponseRedirect(redirect_url)


class TestRealmView(View):
    def post(self, request, *args, **kwargs):
        realm = get_object_or_404(Realm, pk=kwargs["pk"])
        callback = "realms.utils.test_callback"
        callback_kwargs = {}
        redirect_url = None
        try:
            redirect_url = realm.backend_instance.initialize_session(request, callback, **callback_kwargs)
        except Exception:
            logger.exception("Could not get realm %s redirect URL", realm.pk)
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty realm {} redirect URL".format(realm.pk))


class RealmAuthenticationSessionView(CanManageRealmsMixin, DetailView):
    model = RealmAuthenticationSession
    pk_url_kwarg = "ras_pk"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ras = ctx["object"]

        # session expiry
        computed_expiry = ctx["computed_expiry"] = ras.computed_expiry()
        ctx["login_session_expire_at_browser_close"] = computed_expiry == 0
        if ras.expires_at:
            idp_expiry_delta = ras.expires_at - ras.updated_at
            ctx["idp_expiry_age"] = 86400 * idp_expiry_delta.days + idp_expiry_delta.seconds

        # realm user
        realm_user = ctx["realm_user"] = ras.user
        if not realm_user.email:
            ctx["error"] = "Missing email. Cannot be used for Zentral login."

        return ctx


def ras_finalization_error(request, ras, realm_user=None, exception=None):
    ctx = {"realm": ras.realm,
           "message": str(exception)}
    if isinstance(exception, RealmUserError):
        claims = exception.claims
        if claims:
            ctx["original_claims"] = claims.pop("claims", {})
            ctx["claims"] = claims
    if realm_user:
        ctx["original_claims"] = realm_user.claims
        ctx["claims"] = {
            k: v
            for k, v in ((a, getattr(realm_user, a))
                         for a in ("username", "email", "first_name", "last_name", "full_name"))
            if v
        }
    return render(request, "realms/ras_finalization_error.html", ctx, status=503)
