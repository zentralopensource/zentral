import logging
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.generic import View
from .models import Realm


logger = logging.getLogger("zentral.realms.public_views")


# SSO Login


class LoginView(View):
    def dispatch(self, request, *args, **kwargs):
        self.realm = get_object_or_404(Realm, pk=kwargs["pk"], enabled_for_login=True)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        callback = "realms.utils.login_callback"
        callback_kwargs = {}
        if request.method == "POST":
            next_url = request.POST.get(REDIRECT_FIELD_NAME)
            if next_url and url_has_allowed_host_and_scheme(url=next_url,
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
