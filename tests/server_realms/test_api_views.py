from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from .utils import force_realm


class RealmsAPIViewsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.com".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "realms_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # list realms

    def test_list_realms_unauthorized(self):
        response = self.get(reverse("realms_api:realms"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_realms_permission_denied(self):
        response = self.get(reverse("realms_api:realms"))
        self.assertEqual(response.status_code, 403)

    def test_list_realms(self):
        self.set_permissions("realms.view_realm")
        realm = force_realm()
        response = self.get(reverse("realms_api:realms"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'uuid': str(realm.pk),
              'name': realm.name,
              'backend': 'ldap',
              'ldap_config': {
                  "host": "ldap.example.com",
                  "bind_dn": "uid=zentral,ou=Users,o=yolo,dc=example,dc=com",
                  "bind_password": "yolo",
                  "users_base_dn": 'ou=Users,o=yolo,dc=example,dc=com',
              },
              'openidc_config': None,
              'saml_config': None,
              'enabled_for_login': False,
              'user_portal': False,
              'login_session_expiry': 0,
              'username_claim': 'username',
              'email_claim': 'email',
              'first_name_claim': '',
              'last_name_claim': '',
              'full_name_claim': '',
              'custom_attr_1_claim': '',
              'custom_attr_2_claim': '',
              'scim_enabled': False,
              'created_at': realm.created_at.isoformat(),
              'updated_at': realm.updated_at.isoformat()}]
        )

    def test_list_realms_name_filter(self):
        realm = force_realm(backend="saml")
        force_realm()
        self.set_permissions("realms.view_realm")
        response = self.get(reverse("realms_api:realms"), data={"name": realm.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'uuid': str(realm.pk),
              'name': realm.name,
              'backend': 'saml',
              'ldap_config': None,
              'openidc_config': None,
              'saml_config': {
                  "default_relay_state": "29eb0205-3572-4901-b773-fc82bef847ef",
                  "idp_metadata": "<md></md>",
              },
              'enabled_for_login': False,
              'user_portal': False,
              'login_session_expiry': 0,
              'username_claim': 'username',
              'email_claim': 'email',
              'first_name_claim': '',
              'last_name_claim': '',
              'full_name_claim': '',
              'custom_attr_1_claim': '',
              'custom_attr_2_claim': '',
              'scim_enabled': False,
              'created_at': realm.created_at.isoformat(),
              'updated_at': realm.updated_at.isoformat()}]
        )

    # get realm

    def test_get_realm_unauthorized(self):
        realm = force_realm()
        response = self.get(reverse("realms_api:realm", args=(realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_realm_permission_denied(self):
        realm = force_realm()
        response = self.get(reverse("realms_api:realm", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_realm(self):
        realm = force_realm(backend="openidc", user_portal=True)
        self.set_permissions("realms.view_realm")
        response = self.get(reverse("realms_api:realm", args=(realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'uuid': str(realm.pk),
             'name': realm.name,
             'backend': 'openidc',
             'ldap_config': None,
             'openidc_config': {
                 "client_id": "yolo",
                 "client_secret": "fomo",
                 "discovery_url": "https://zentral.example.com/.well-known/openid-configuration",
                 "extra_scopes": ["profile"],
             },
             'saml_config': None,
             'enabled_for_login': False,
             'user_portal': True,
             'login_session_expiry': 0,
             'username_claim': 'username',
             'email_claim': 'email',
             'first_name_claim': '',
             'last_name_claim': '',
             'full_name_claim': '',
             'custom_attr_1_claim': '',
             'custom_attr_2_claim': '',
             'scim_enabled': False,
             'created_at': realm.created_at.isoformat(),
             'updated_at': realm.updated_at.isoformat()}
        )

    # create realm

    def test_create_realm_unauthorized(self):
        response = self.post(reverse("realms_api:realms"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_realm_permission_denied(self):
        response = self.post(reverse("realms_api:realms"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_realm_method_not_allowed(self):
        self.set_permissions("realms.add_realm")
        response = self.post(reverse("realms_api:realms"), {})
        self.assertEqual(response.status_code, 405)

    # update realm

    def test_update_realm_unauthorized(self):
        realm = force_realm()
        response = self.put(reverse("realms_api:realm", args=(realm.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_realm_permission_denied(self):
        realm = force_realm()
        response = self.put(reverse("realms_api:realm", args=(realm.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_realm_method_not_allowed(self):
        realm = force_realm()
        self.set_permissions("realms.change_realm")
        response = self.put(reverse("realms_api:realm", args=(realm.pk,)), {})
        self.assertEqual(response.status_code, 405)

    # delete realm

    def test_delete_realm_unauthorized(self):
        realm = force_realm()
        response = self.delete(reverse("realms_api:realm", args=(realm.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_realm_permission_denied(self):
        realm = force_realm()
        response = self.delete(reverse("realms_api:realm", args=(realm.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_realm_method_not_allowed(self):
        realm = force_realm()
        self.set_permissions("realms.delete_realm")
        response = self.delete(reverse("realms_api:realm", args=(realm.pk,)))
        self.assertEqual(response.status_code, 405)
