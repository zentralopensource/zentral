import uuid

from accounts.models import User
from django.contrib.auth.models import Group
from django.utils.crypto import get_random_string
from realms.models import (
    Realm,
    RealmAuthenticationSession,
    RealmEmail,
    RealmGroup,
    RealmGroupMapping,
    RealmUser,
    RealmUserGroupMembership,
    RoleMapping,
)

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


def force_realm(backend="ldap", enabled_for_login=False, user_portal=False):
    if backend == "ldap":
        config = {
            "host": "ldap.example.com",
            "bind_dn": "uid=zentral,ou=Users,o=yolo,dc=example,dc=com",
            "bind_password": "yolo",
            "users_base_dn": 'ou=Users,o=yolo,dc=example,dc=com',
        }
    elif backend == "openidc":
        config = {
            "client_id": "yolo",
            "client_secret": "fomo",
            "discovery_url": "https://zentral.example.com/.well-known/openid-configuration",
            "extra_scopes": ["profile"],
        }
    elif backend == "saml":
        config = {
            'default_relay_state': "29eb0205-3572-4901-b773-fc82bef847ef",
            'idp_metadata': "<md></md>"
        }
    else:
        raise ValueError("Unknown backend")
    return Realm.objects.create(
        name=get_random_string(12),
        backend=backend,
        config=config,
        username_claim="username",
        email_claim="email",
        enabled_for_login=enabled_for_login,
        user_portal=user_portal,
    )


def force_realm_user(
    realm=None,
    email_count=0,
    group=None,
):
    if not realm:
        realm = force_realm()
    username = get_random_string(12)
    email = f"{username}@zentral.com"
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        first_name=get_random_string(12),
        last_name=get_random_string(12),
        email=email,
        scim_external_id=str(uuid.uuid4()).replace("-", "")[:10] if realm.scim_enabled else None,
        scim_active=realm.scim_enabled,
    )
    for idx in range(email_count):
        RealmEmail.objects.create(user=realm_user,
                                  primary=idx == 0,
                                  type="work",
                                  email=email if idx == 0 else f"{get_random_string(12)}@zentral.com")
    if group:
        RealmUserGroupMembership.objects.create(user=realm_user, group=group)
    return realm, realm_user


def force_realm_group(realm=None, parent=None, display_name=None):
    if not realm:
        realm = force_realm()
    return RealmGroup.objects.create(
        realm=realm,
        display_name=display_name or get_random_string(12),
        parent=parent,
        scim_managed=realm.scim_enabled,
        scim_external_id=str(uuid.uuid4()).replace("-", "")[:10] if realm.scim_enabled else None,
    )


def force_realm_group_mapping(realm=None, realm_group=None):
    if not realm:
        realm = force_realm()
    if not realm_group:
        realm_group = force_realm_group(realm=realm)
    return RealmGroupMapping.objects.create(
        claim=get_random_string(12),
        value=get_random_string(12),
        realm_group=realm_group,
    )


def force_group():
    return Group.objects.create(name=get_random_string(12))


def force_role_mapping(realm=None, group=None):
    if not group:
        group = force_group()
    realm_group = force_realm_group(realm=realm)
    return RoleMapping.objects.create(
        realm_group=realm_group,
        group=group,
    )


def force_user(username=None, email=None, active=True, remote=False, service_account=False):
    if not username:
        username = get_random_string(12)
    if not email:
        email = get_random_string(12) + "@zentral.com"
    user = User(
        username=username,
        email=email,
        first_name=get_random_string(12),
        last_name=get_random_string(12),
        is_active=active,
        is_remote=remote,
        is_service_account=service_account,
    )
    user.set_password(get_random_string(12))
    user.save()
    return user


def force_realm_authentication_session(callback="realms.utils.test_callback"):
    realm = force_realm(enabled_for_login=True)
    _, realm_user = force_realm_user(realm=realm)
    return RealmAuthenticationSession.objects.create(
        realm=realm,
        user=realm_user,
        callback=callback,
    )
