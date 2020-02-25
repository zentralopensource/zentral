import logging
from xml.etree import ElementTree
from django.urls import reverse
from saml2 import BINDING_HTTP_POST, md, saml, samlp, xmlenc, xmldsig
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config
from saml2.saml import NAMEID_FORMAT_EMAILADDRESS
from zentral.conf import settings
from realms.backends.base import BaseBackend


logger = logging.getLogger("zentral.realms.backends.saml")


class SAMLRealmBackend(BaseBackend):
    name = "SAML"

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
        yield from [
            ("Entity ID", self.entity_id()),
            ("Assertion Consumer Service URL", self.acs_url()),
        ]
        config = self.instance.config
        for field_name in self.get_form_class().CLAIM_FIELD_NAMES:
            value = config.get(field_name)
            if value:
                yield (field_name.replace("_", " ").title(), value)

    def initialize_session(self, callback, **callback_kwargs):
        from realms.models import RealmAuthenticationSession
        ras = RealmAuthenticationSession(
            realm=self.instance,
            callback=callback,
            callback_kwargs=callback_kwargs
        )
        ras.save()
        ras.refresh_from_db()
        saml2_client = self.get_saml2_client()
        _, request_info = saml2_client.prepare_for_authenticate(relay_state=str(ras.pk))
        return dict(request_info["headers"])["Location"]

    def update_or_create_realm_user(self, session_info):
        # cleanup name id
        name_id = None
        if 'name_id' in session_info:
            name_id = session_info.pop('name_id').text
            session_info['name_id'] = name_id

        # try to get the configured claims
        config = self.instance.config
        extracted_claims = {}
        ava = session_info.get('ava')
        if ava:
            for field_name in self.get_form_class().CLAIM_FIELD_NAMES:
                attr = config.get(field_name)
                val = ava.get(attr)
                if val:
                    # TODO: only the first value at the moment
                    extracted_claims[field_name.replace("_claim", "")] = val[0]

        # the username from the extracted claims
        username = extracted_claims.get("username")

        # alternatively, use name_id if possible
        if not username and name_id:
            username = name_id

        if not username:
            logger.error("No username found in SAML session info")
            return None
        else:
            claims = session_info
            claims["_zentral"] = extracted_claims
            from realms.models import RealmUser
            realm_user, _ = RealmUser.objects.update_or_create(
                realm=self.instance,
                username=username,
                defaults={
                    "claims": claims,
                }
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
