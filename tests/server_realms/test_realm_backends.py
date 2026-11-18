import base64
import hashlib
import uuid
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlparse

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmAuthenticationSession
import requests
import responses

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
            email_claim="email",
            config={"discovery_url": "https://issuer.example.com/.well-knowm/openid-configuration",
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

    @patch("realms.backends.openidc.lib.get_openid_configuration")
    def test_openidc_login(self, get_openid_configuration):
        authorization_endpoint_url = "https://www.example.com/authorization"
        get_openid_configuration.return_value = {
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
        self.assertEqual(query["nonce"], [ras.backend_state["nonce"]])
        self.assertGreaterEqual(len(ras.backend_state["nonce"]), 43)
        # no client secret: PKCE with S256, RFC 7636 §4.2
        self.assertEqual(query["code_challenge_method"], ["S256"])
        code_verifier = ras.backend_state["code_verifier"]
        self.assertEqual(
            query["code_challenge"],
            [base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest()).rstrip(b"=").decode()]
        )
        get_openid_configuration.assert_called_once_with(self.openidc_realm.config["discovery_url"])

    @patch("realms.backends.openidc.lib.get_openid_configuration")
    def test_openidc_login_client_secret_no_pkce(self, get_openid_configuration):
        get_openid_configuration.return_value = {"authorization_endpoint": "https://www.example.com/authorization"}
        realm = Realm.objects.create(
            name=get_random_string(12),
            backend="openidc",
            username_claim="username",
            config={"discovery_url": "https://issuer.example.com/.well-known/openid-configuration",
                    "client_id": str(uuid.uuid4()),
                    "client_secret": get_random_string(12),
                    "extra_scopes": []},
            enabled_for_login=True
        )
        response = self.client.post(reverse("realms_public:login", args=(realm.pk,)), {"next": "/"})
        ras = RealmAuthenticationSession.objects.get(realm=realm)
        self.assertEqual(list(ras.backend_state.keys()), ["nonce"])
        query = parse_qs(urlparse(response.url).query)
        self.assertEqual(query["state"], [str(ras.pk)])
        self.assertEqual(query["nonce"], [ras.backend_state["nonce"]])
        self.assertNotIn("code_challenge_method", query)
        self.assertNotIn("code_challenge", query)

    def _openidc_redirect(self, backend_state, id_token_claims, userinfo=True):
        username = get_random_string(12)
        with patch("realms.backends.openidc.lib.get_openid_configuration") as get_openid_configuration, \
             patch("realms.backends.openidc.lib.verify_jws") as verify_jws, \
             responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.post("https://issuer.example.com/token", json={
                "id_token": "bla",
                "access_token": "hoho",
                "issuer": "https://issuer.example.com",
            })
            if userinfo:
                rsps.get("https://issuer.example.com/user-info", json={
                    "sub": username,
                    "username": username,
                    "email": f"{username}@example.com",
                })
            verify_jws.return_value = {
                "iss": "https://issuer.example.com",
                "aud": self.openidc_realm.config["client_id"],
                "sub": username,
                **id_token_claims,
            }
            get_openid_configuration.return_value = {
                "issuer": "https://issuer.example.com",
                "token_endpoint": "https://issuer.example.com/token",
                "userinfo_endpoint": "https://issuer.example.com/user-info",
            }
            ras = RealmAuthenticationSession.objects.create(
                realm=self.openidc_realm,
                backend_state=backend_state,
                callback="realms.utils.login_callback",
                callback_kwargs={"next_url": "/"},
            )
            params = urlencode({"state": str(ras.pk), "code": "the-code"})
            session = self.client.session
            session[f"realm_{self.openidc_realm.pk}_session"] = str(ras.pk)
            session.save()
            response = self.client.get(
                reverse("realms_public:openidc_ac_redirect", args=(self.openidc_realm.pk,)) + f"?{params}",
                follow=True,
            )
            token_request = rsps.calls[0].request
        ras.refresh_from_db()
        return response, ras, username, token_request

    def test_openidc_redirect(self):
        response, ras, username, token_request = self._openidc_redirect(
            {"nonce": "the-nonce", "code_verifier": "the-verifier"},
            {"nonce": "the-nonce"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"].username, username)
        self.assertEqual(response.context["user"].email, f"{username}@example.com")
        self.assertTemplateUsed(response, "base/index.html")
        self.assertEqual(token_request.url, "https://issuer.example.com/token")
        self.assertEqual(parse_qs(token_request.body)["code_verifier"], ["the-verifier"])

    def test_openidc_redirect_invalid_nonce(self):
        for backend_state, id_token_claims in (
            ({"nonce": "the-nonce"}, {"nonce": "another-nonce"}),
            ({"nonce": "the-nonce"}, {}),
            ({"nonce": "the-nonce"}, {"nonce": ["the-nonce"]}),
            ({"nonce": "the-nonce"}, {"nonce": "the-nonce-é"}),
            ({"nonce": "the-nonce"}, {"nonce": "the-nonce-\ud800"}),
            # a session started before the nonce was sent
            ({"code_verifier": "the-verifier"}, {"nonce": "the-nonce"}),
            (None, {}),
        ):
            response, ras, _, _ = self._openidc_redirect(backend_state, id_token_claims, userinfo=False)
            self.assertEqual(response.status_code, 400)
            self.assertIsNone(ras.user)

    @patch("realms.backends.openidc.lib.get_openid_configuration")
    def test_openidc_redirect_identity_provider_error(self, get_openid_configuration):
        get_openid_configuration.side_effect = requests.Timeout("Boom!!!")
        ras = RealmAuthenticationSession.objects.create(
            realm=self.openidc_realm,
            backend_state=None,
            callback="realms.utils.login_callback",
            callback_kwargs={"next_url": "/"},
        )
        session = self.client.session
        session[f"realm_{self.openidc_realm.pk}_session"] = str(ras.pk)
        session.save()
        params = urlencode({"state": str(ras.pk), "code": "the-code"})
        response = self.client.get(
            reverse("realms_public:openidc_ac_redirect", args=(self.openidc_realm.pk,)) + f"?{params}"
        )
        self.assertEqual(response.status_code, 503)
        self.assertTemplateUsed(response, "realms/ras_finalization_error.html")
        self.assertEqual(response.context["message"], "Could not get the OpenID configuration")
        ras.refresh_from_db()
        self.assertIsNone(ras.user)

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
