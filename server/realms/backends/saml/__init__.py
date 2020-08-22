import logging
from xml.etree import ElementTree
from django.urls import reverse
from saml2 import BINDING_HTTP_POST, md, saml, samlp, xmlenc, xmldsig
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from zentral.conf import settings
from realms.backends.base import BaseBackend
from realms.exceptions import RealmUserError


logger = logging.getLogger("zentral.realms.backends.saml")


class SAMLRealmBackend(BaseBackend):
    name = "SAML"

    @property
    def allow_idp_initiated_login(self):
        return self.instance.enabled_for_login and (self.instance.config.get("allow_idp_initiated_login") or False)

    @property
    def default_relay_state(self):
        return self.instance.enabled_for_login and self.instance.config.get("default_relay_state")

    def acs_url(self):
        "Assertion Consumer Service URL"
        return "{}{}".format(settings["api"]["tls_hostname"].rstrip("/"),
                             reverse("realms:saml_acs", args=(self.instance.uuid,)))

    def entity_id(self):
        """
        see https://pysaml2.readthedocs.io/en/latest/howto/config.html#entityid
        The globally unique identifier of the entity.
        It is recommended that the entityid should point to a real webpage where
        the metadata for the entity can be found.

        """
        return "{}{}".format(settings["api"]["tls_hostname"].rstrip("/"),
                             reverse("realms:saml_metadata", args=(self.instance.uuid,)))

    def get_saml2_config(self):
        settings = {
            "metadata": {
                "inline": [self.instance.config["idp_metadata"]],
            },
            "entityid": self.entity_id(),
            "service": {
                "sp": {
                    "name_id_format": NAMEID_FORMAT_EMAILADDRESS,
                    "endpoints": {
                        "assertion_consumer_service": [
                            (self.acs_url(), BINDING_HTTP_POST),
                        ],
                    },
                    # skip built-in pysaml2 cache
                    # https://github.com/IdentityPython/pysaml2/blob/9e5c9ab426ce8e602ca769c7fc259a2fb1325877/example/sp-wsgi/sp.py#L353  # NOQA
                    "allow_unsolicited": True,

                    "authn_requests_signed": False,
                    "logout_requests_signed": True,
                    "want_assertions_signed": True,
                    "want_response_signed": False,
                },
            },
        }
        sp_config = Saml2Config()
        sp_config.allow_unknown_attributes = True
        sp_config.load(settings)
        return sp_config

    def get_saml2_client(self):
        return Saml2Client(config=self.get_saml2_config())

    def extra_attributes_for_display(self):
        attributes = [
            ("Entity ID", self.entity_id(), False),
            ("Assertion Consumer Service URL", self.acs_url(), False),
            ("Allow IdP-initiated login", "yes" if self.allow_idp_initiated_login else "no", False),
        ]
        if self.default_relay_state:
            attributes.append(("Default relay state", self.default_relay_state, False))
        return attributes

    def initialize_session(self, request, callback, **callback_kwargs):
        from realms.models import RealmAuthenticationSession
        ras = RealmAuthenticationSession(
            realm=self.instance,
            callback=callback,
            callback_kwargs=callback_kwargs
        )
        ras.save()

        saml2_client = self.get_saml2_client()
        request_id, request_info = saml2_client.prepare_for_authenticate(relay_state=str(ras.pk))

        # save request ID in auth session
        ras.backend_state = {"request_id": request_id}
        ras.save()

        return dict(request_info["headers"])["Location"]

    def update_or_create_realm_user(self, session_info):
        # cleanup name id
        name_id = None
        if 'name_id' in session_info:
            name_id = session_info.pop('name_id').text
            session_info['name_id'] = name_id

        # default realm user attributes for update or create
        realm_user_defaults = {"claims": session_info}

        # try to get the configured claims
        ava = session_info.get('ava')
        if ava:
            for user_claim, user_claim_source in self.instance.iter_user_claim_mappings():
                value = ava.get(user_claim_source)
                if value:
                    # TODO: only the first value at the moment
                    value = value[0]
                if not value:
                    value = ""
                realm_user_defaults[user_claim] = value

        # the username from the claim mappings
        username = realm_user_defaults.pop("username", None)

        # alternatively, use name_id if possible
        if not username and name_id:
            username = name_id

        if not username:
            raise RealmUserError("No username found in SAML session info", realm_user_defaults)
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
        from .forms import SAMLRealmForm
        return SAMLRealmForm


# adapted from https://github.com/knaperek/djangosaml2/blob/master/djangosaml2/views.py


def register_namespace_prefixes():
    prefixes = (('saml', saml.NAMESPACE),
                ('samlp', samlp.NAMESPACE),
                ('md', md.NAMESPACE),
                ('ds', xmldsig.NAMESPACE),
                ('xenc', xmlenc.NAMESPACE))
    for prefix, namespace in prefixes:
        ElementTree.register_namespace(prefix, namespace)


register_namespace_prefixes()
