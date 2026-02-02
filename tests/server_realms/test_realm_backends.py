import uuid
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmAuthenticationSession

from zentral.conf import settings

from .utils import SAML2_IDP_METADATA_TEST_STRING


class RealmBackendsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.ldap_realm_no_login = Realm.objects.create(
            name=get_random_string(12),
            backend="ldap",
            username_claim="username",
        )
        cls.ldap_realm = Realm.objects.create(
            name=get_random_string(12),
            backend="ldap",
            username_claim="username",
            enabled_for_login=True
        )
        cls.openidc_realm = Realm.objects.create(
            name=get_random_string(12),
            backend="openidc",
            username_claim="username",
            config={"discovery_url": "https://www.example.com/discovery",
                    "client_id": str(uuid.uuid4()),
                    "extra_scopes": []},
            enabled_for_login=True
        )
        cls.saml_realm = Realm.objects.create(
            name=get_random_string(12),
            backend="saml",
            username_claim="username",
            config={"idp_metadata": SAML2_IDP_METADATA_TEST_STRING},
            enabled_for_login=True
        )

    def test_ldap_no_login(self):
        response = self.client.post(reverse("realms_public:login", args=(self.ldap_realm_no_login.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_ldap_login(self):
        next_url = "/{}".format(get_random_string(12))
        response = self.client.post(
            reverse("realms_public:login", args=(self.ldap_realm.pk,)),
            {"next": next_url + "\u0000"}
        )
        ras = RealmAuthenticationSession.objects.filter(realm=self.ldap_realm).order_by("-created_at")[0]
        self.assertEqual(ras.callback, "realms.utils.login_callback")
        self.assertEqual(ras.callback_kwargs, {"next_url": next_url})
        self.assertRedirects(response, reverse("realms_public:ldap_login", args=(ras.realm.pk, ras.pk)))

    @patch("realms.backends.openidc.lib._get_openid_configuration")
    def test_openidc_login(self, _get_openid_configuration):
        authorization_endpoint_url = "https://www.example.com/authorization"
        _get_openid_configuration.return_value = {
            "authorization_endpoint": authorization_endpoint_url
        }
        next_url = "/{}".format(get_random_string(12))
        response = self.client.post(
            reverse("realms_public:login", args=(self.openidc_realm.pk,)),
            {"next": next_url + "\u0000"}
        )
        ras = RealmAuthenticationSession.objects.filter(realm=self.openidc_realm).order_by("-created_at")[0]
        self.assertEqual(ras.callback, "realms.utils.login_callback")
        self.assertEqual(ras.callback_kwargs, {"next_url": next_url})
        url = urlparse(response.url)
        auth_url = urlparse(authorization_endpoint_url)
        self.assertEqual(url.scheme, auth_url.scheme)
        self.assertEqual(url.netloc, auth_url.netloc)
        self.assertEqual(url.path, auth_url.path)
        query = parse_qs(url.query)
        self.assertEqual(query["client_id"], [self.openidc_realm.config["client_id"]])
        self.assertEqual(
            query["redirect_uri"],
            ["https://{}{}".format(settings["api"]["fqdn"],
                                   reverse("realms_public:openidc_ac_redirect", args=(self.openidc_realm.pk,)))]
        )
        self.assertEqual(query["state"], [str(ras.pk)])
        _get_openid_configuration.assert_called_once_with(self.openidc_realm.config["discovery_url"])

    def test_saml_login(self):
        next_url = "/{}".format(get_random_string(12))
        response = self.client.post(
            reverse("realms_public:login", args=(self.saml_realm.pk,)),
            {"next": next_url + "\u0000"}
        )
        ras = RealmAuthenticationSession.objects.filter(realm=self.saml_realm).order_by("-created_at")[0]
        self.assertEqual(ras.callback, "realms.utils.login_callback")
        self.assertEqual(ras.callback_kwargs, {"next_url": next_url})
        url = urlparse(response.url)
        self.assertEqual(url.scheme, "https")
        self.assertEqual(url.netloc, "zentral")
        self.assertEqual(url.path, "/simplesaml/saml2/idp/metadata.php")
        query = parse_qs(url.query)
        self.assertTrue("SAMLRequest" in query)
        self.assertEqual(query["RelayState"], [str(ras.pk)])
