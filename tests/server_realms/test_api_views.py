from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from .utils import force_realm


class RealmsAPIViewsTestCase(TestCase):
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
        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utility methods

    def set_permissions(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def post(self, *args, **kwargs):
        return self._make_request(self.client.post, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

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
