from unittest.mock import patch
from urllib.parse import urlparse, parse_qs
import uuid
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmAuthenticationSession
from zentral.conf import settings


SAML2_IDP_METADATA_TEST_STRING = """
<EntitiesDescriptor
    xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    xmlns:shibmeta="urn:mace:shibboleth:metadata:1.0"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    Name="urn:mace:example.com:test-1.0">
  <EntityDescriptor
    entityID="https://zentral/simplesaml/saml2/idp/metadata.php"
    xml:base="swamid-1.0/idp.umu.se-saml2.xml">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor>
      <ds:KeyInfo>
        <ds:X509Data>
          <ds:X509Certificate>-----BEGIN CERTIFICATE-----
MIIDcjCCAlqgAwIBAgIJAMeNOz7VOb0iMA0GCSqGSIb3DQEBCwUAMIGFMQswCQYD
VQQGEwJERTEQMA4GA1UECBMHSGFtYnVyZzEQMA4GA1UEBxMHSGFtYnVyZzEQMA4G
A1UEChMHWmVudHJhbDELMAkGA1UECxMCSVQxEzARBgNVBAMTClplbnRyYWwgQ0Ex
HjAcBgkqhkiG9w0BCQEWD2luZm9AemVudHJhbC5pbzAeFw0xOTA2MjcxMDU2MDVa
Fw0yOTA2MjQxMDU2MDVaMBIxEDAOBgNVBAMMB3plbnRyYWwwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCosp85fMRY3qIFUTZjX3mYwZI3i+B23clpqTqh
zL7yROKIHJ59HysYY2OlZ9zcXP8+3HUsnA12YnY+sHJw7BELsFJq1whu6b3xe0nK
IFWs7dOWaEPk3GcOoDWTlhto3bM2yAYyZvWySsYdsdKlKwhZOn8IHrIV5lCvW2CZ
ewCYjYFQIxO9k7pVlS+KKHvSe9NWR3SKJiC57x5miUzljpRU7do2ktyTv/Bj7D6Z
dhZ3+DfWxpcddfkqk97Nc2uXOypHtcozT3ZXcTv/v8fLX6IQXEIey4DeIK2ntV4m
YQzmc2ERmSrfcS/tMK0/j+e+aBBrKxd+Or8vpZLwjr2+N2KrAgMBAAGjVzBVMCcG
A1UdEQQgMB6CB3plbnRyYWyCE3plbnRyYWwtY2xpY2VydGF1dGgwCwYDVR0PBAQD
AgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDBDANBgkqhkiG9w0BAQsF
AAOCAQEAbhtQtlT2ljJegcVZR99Kqb31gCgWsJCGluzdSVpQ6d7u1RXiQXmqgO5W
cJyQekaSRwfjNYRtOK3qxJoAe/67t5cOFnSy00RdHgeQJnhzbhauD7ELW3UPW26r
M3/hrpMTwmJaqa5ZHAygwMCEcsasB5WFDQCZuVOTpYBv21IIgqG6REskf1Xx8Xmd
1BXmOL0TEIjnWqOkm77WLMH1hnxHMorztE5O1V8JCcM46u1l5y3cp/rStPPzg1ky
rADUMx83/gKFjdKEuDtFCSwNs9KOzXjeeysD39Mv7e54e74Y5kSP+W/hUxaIX0oL
KKbzX9i21E/u9379kpBdfZE18RWsDw==
-----END CERTIFICATE-----</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDFormat>
    <SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://zentral/simplesaml/saml2/idp/metadata.php"/>
  </IDPSSODescriptor>
  <Organization>
    <OrganizationName xml:lang="en">Zentral</OrganizationName>
    <OrganizationDisplayName xml:lang="en">Zentral</OrganizationDisplayName>
    <OrganizationURL xml:lang="en">https://zentral.io</OrganizationURL>
  </Organization>
  <ContactPerson contactType="technical">
    <SurName>MoreSpam</SurName>
    <EmailAddress>spam-us-from-the-zentral-tests@zentral.io</EmailAddress>
  </ContactPerson>
</EntityDescriptor>
</EntitiesDescriptor>
"""


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class RealmModelsTestCase(TestCase):
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
