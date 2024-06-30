from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import APIToken, User
from .utils import force_scep_config


class MDMSCEPConfigAPIViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])
        cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

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

    # list push certificates

    def test_list_scep_configs_unauthorized(self):
        response = self.get(reverse("mdm_api:scep_configs"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_scep_configs_permission_denied(self):
        response = self.get(reverse("mdm_api:scep_configs"))
        self.assertEqual(response.status_code, 403)

    def test_list_scep_configs(self):
        self.set_permissions("mdm.view_scepconfig")
        scep_config = force_scep_config()
        response = self.get(reverse("mdm_api:scep_configs"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'allow_all_apps_access': False,
              'challenge_type': 'STATIC',
              'created_at': scep_config.created_at.isoformat(),
              'id': scep_config.pk,
              'key_is_extractable': False,
              'key_usage': 0,
              'keysize': 2048,
              'microsoft_ca_challenge_kwargs': None,
              'name': scep_config.name,
              'okta_ca_challenge_kwargs': None,
              'provisioning_uid': None,
              'static_challenge_kwargs': {'challenge': scep_config.get_challenge_kwargs()['challenge']},
              'updated_at': scep_config.updated_at.isoformat(),
              'url': scep_config.url}]
        )

    def test_list_scep_configs_name_filter(self):
        scep_config = force_scep_config()
        force_scep_config()
        self.set_permissions("mdm.view_scepconfig")
        response = self.get(reverse("mdm_api:scep_configs"), data={"name": scep_config.name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            [{'allow_all_apps_access': False,
              'challenge_type': 'STATIC',
              'created_at': scep_config.created_at.isoformat(),
              'id': scep_config.pk,
              'key_is_extractable': False,
              'key_usage': 0,
              'keysize': 2048,
              'microsoft_ca_challenge_kwargs': None,
              'name': scep_config.name,
              'okta_ca_challenge_kwargs': None,
              'provisioning_uid': None,
              'static_challenge_kwargs': {'challenge': scep_config.get_challenge_kwargs()['challenge']},
              'updated_at': scep_config.updated_at.isoformat(),
              'url': scep_config.url}]
        )

    # get scep_config

    def test_get_scep_config_unauthorized(self):
        scep_config = force_scep_config()
        response = self.get(reverse("mdm_api:scep_config", args=(scep_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_get_scep_config_permission_denied(self):
        scep_config = force_scep_config()
        response = self.get(reverse("mdm_api:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_get_scep_config(self):
        scep_config = force_scep_config()
        self.set_permissions("mdm.view_scepconfig")
        response = self.get(reverse("mdm_api:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'allow_all_apps_access': False,
             'challenge_type': 'STATIC',
             'created_at': scep_config.created_at.isoformat(),
             'id': scep_config.pk,
             'key_is_extractable': False,
             'key_usage': 0,
             'keysize': 2048,
             'microsoft_ca_challenge_kwargs': None,
             'name': scep_config.name,
             'okta_ca_challenge_kwargs': None,
             'provisioning_uid': None,
             'static_challenge_kwargs': {'challenge': scep_config.get_challenge_kwargs()['challenge']},
             'updated_at': scep_config.updated_at.isoformat(),
             'url': scep_config.url}
        )

    def test_get_provisioned_scep_config(self):
        scep_config = force_scep_config(provisioning_uid="YoLoFoMo")
        self.set_permissions("mdm.view_scepconfig")
        response = self.get(reverse("mdm_api:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            # no challenge related attributes
            {'allow_all_apps_access': False,
             'created_at': scep_config.created_at.isoformat(),
             'id': scep_config.pk,
             'key_is_extractable': False,
             'key_usage': 0,
             'keysize': 2048,
             'name': scep_config.name,
             'provisioning_uid': "YoLoFoMo",
             'updated_at': scep_config.updated_at.isoformat(),
             'url': scep_config.url}
        )

    # create scep_config

    def test_create_scep_config_unauthorized(self):
        response = self.post(reverse("mdm_api:scep_configs"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_scep_config_permission_denied(self):
        response = self.post(reverse("mdm_api:scep_configs"), {})
        self.assertEqual(response.status_code, 403)

    def test_create_scep_config_method_not_allowed(self):
        self.set_permissions("mdm.add_scepconfig")
        response = self.post(reverse("mdm_api:scep_configs"), {})
        self.assertEqual(response.status_code, 405)

    # update scep_config

    def test_update_scep_config_unauthorized(self):
        scep_config = force_scep_config()
        response = self.put(reverse("mdm_api:scep_config", args=(scep_config.pk,)), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_update_scep_config_permission_denied(self):
        scep_config = force_scep_config()
        response = self.put(reverse("mdm_api:scep_config", args=(scep_config.pk,)), {})
        self.assertEqual(response.status_code, 403)

    def test_update_scep_config_method_not_allowed(self):
        scep_config = force_scep_config()
        self.set_permissions("mdm.change_scepconfig")
        response = self.put(reverse("mdm_api:scep_config", args=(scep_config.pk,)), {})
        self.assertEqual(response.status_code, 405)

    # delete scep_config

    def test_delete_scep_config_unauthorized(self):
        scep_config = force_scep_config()
        response = self.delete(reverse("mdm_api:scep_config", args=(scep_config.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_delete_scep_config_permission_denied(self):
        scep_config = force_scep_config()
        response = self.delete(reverse("mdm_api:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_scep_config_method_not_allowed(self):
        scep_config = force_scep_config()
        self.set_permissions("mdm.delete_scepconfig")
        response = self.delete(reverse("mdm_api:scep_config", args=(scep_config.pk,)))
        self.assertEqual(response.status_code, 405)
