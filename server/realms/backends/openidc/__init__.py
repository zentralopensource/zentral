import logging
from django.urls import reverse
from zentral.conf import settings
from realms.backends.base import BaseBackend


logger = logging.getLogger("zentral.realms.backends.openidc")


class OpenIDConnectRealmBackend(BaseBackend):
    name = "OpenID Connect"

    def ac_redirect_uri(self):
        "Authorization code flow redirect URI"
        return "{}{}".format(settings["api"]["tls_hostname"].rstrip("/"),
                             reverse("realms:openidc_ac_redirect", args=(self.instance.uuid,)))

    def extra_attributes_for_display(self):
        return [
            ("Authorization code flow redirect URI", self.ac_redirect_uri()),
        ]

    def initialize_session(self, callback, **callback_kwargs):
        from realms.models import RealmAuthenticationSession
        ras = RealmAuthenticationSession(
            realm=self.instance,
            callback=callback,
            callback_kwargs=callback_kwargs
        )
        ras.save()
        # TODO: make verification_code / verifier. return redirect URI

    def update_or_create_realm_user(self, authorization_code):
        # TODO: exchange authorization_code for id token / access tokens
        # use the info to update or create a realm user and return it
        pass

    @staticmethod
    def get_form_class():
        # to avoid import loop
        # backends loaded from models
        # but backend form loads models…
        from .forms import OpenIDConnectRealmForm
        return OpenIDConnectRealmForm
