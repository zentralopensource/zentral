from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.views.generic import FormView
from realms.models import RealmAuthenticationSession
from .forms import LoginForm


class LoginView(FormView):
    form_class = LoginForm
    template_name = "realms/ldap_login_form.html"

    def dispatch(self, request, *args, **kwargs):
        # realm authentication session
        uuid = kwargs.pop("uuid")
        session_pk = kwargs.pop("session_pk")
        self.session = get_object_or_404(
            RealmAuthenticationSession,
            realm__pk=uuid, pk=session_pk,
            realm__backend="ldap",
            user__isnull=True
        )
        self.backend_instance = self.session.realm.backend_instance
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["hide_default_sign_in"] = True
        ctx["session"] = self.session
        ctx["realm"] = self.session.realm
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["backend_instance"] = self.backend_instance
        return kwargs

    def form_valid(self, form):
        username = form.cleaned_data["username"]

        realm_user = self.backend_instance.update_or_create_realm_user(username)

        # finalize the authentication session
        redirect_url = None
        try:
            redirect_url = self.session.finalize(self.request, realm_user)
        except Exception:
            raise
            raise ValueError("Could not finalize the authentication session")
        else:
            if redirect_url:
                return HttpResponseRedirect(redirect_url)
            else:
                raise ValueError("Empty authentication session redirect url")
