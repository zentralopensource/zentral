import logging
from django.urls import reverse
from zentral.conf import settings
from realms.backends.base import BaseBackend
from .lib import build_authorization_code_flow_url, generate_pkce_codes, get_claims


logger = logging.getLogger("zentral.realms.backends.openidc")


class OpenIDConnectRealmBackend(BaseBackend):
    name = "OpenID Connect"

    def ac_redirect_uri(self):
        "Authorization code flow redirect URI"
        return "{}{}".format(settings["api"]["tls_hostname"].rstrip("/"),
                             reverse("realms:openidc_ac_redirect", args=(self.instance.uuid,)))

    def extra_attributes_for_display(self):
        config = self.instance.config
        return [
            ("Discovery URL", config.get("discovery_url")),
            ("Client ID", config.get("client_id")),
            ("Client secret", config.get("client_secret")),
            ("Authorization code flow redirect URI", self.ac_redirect_uri()),
        ]

    def initialize_session(self, callback, **callback_kwargs):
        config = self.instance.config

        if not config.get("client_secret"):
            # PKCE
            code_challenge, code_verifier = generate_pkce_codes()
            backend_state = {"code_verifier": code_verifier}
        else:
            # client secret
            code_challenge = None
            backend_state = None

        from realms.models import RealmAuthenticationSession
        ras = RealmAuthenticationSession(
            realm=self.instance,
            backend_state=backend_state,
            callback=callback,
            callback_kwargs=callback_kwargs
        )
        ras.save()

        return build_authorization_code_flow_url(
            config["discovery_url"],
            config["client_id"],
            self.ac_redirect_uri(),
            config["extra_scopes"],
            str(ras.pk),
            code_challenge
        )

    def update_or_create_realm_user(self, authorization_code, code_verifier):
        config = self.instance.config
        claims = get_claims(
            config["discovery_url"],
            config["client_id"],
            self.ac_redirect_uri(),
            authorization_code,
            config.get("client_secret"),
            code_verifier
        )

        # default realm user attributes for update or create
        realm_user_defaults = {"claims": claims}

        for user_claim, user_claim_source in self.instance.iter_user_claim_mappings():
            value = claims.get(user_claim_source) or ""
            realm_user_defaults[user_claim] = value

        # the username for the claim mappings
        username = realm_user_defaults.pop("username", None)
        if not username:
            logger.error("No username found in ID token")
            return None
        else:
            from realms.models import RealmUser
            realm_user, _ = RealmUser.objects.update_or_create(
                realm=self.instance,
                username=username,
                defaults=realm_user_defaults
            )
            return realm_user

    @staticmethod
    def get_form_class():
        # to avoid import loop
        # backends loaded from models
        # but backend form loads models…
        from .forms import OpenIDConnectRealmForm
        return OpenIDConnectRealmForm
