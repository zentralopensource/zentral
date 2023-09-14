from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import APIToken, User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SoftwareUpdatesAPIViewsTestCase(TestCase):
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

    def post(self, url, include_token=True):
        kwargs = {}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(url, **kwargs)

    # sync_software_updates

    def test_sa_sync_software_updates_unauthorized(self):
        response = self.post(reverse("mdm_api:sync_software_updates"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_sa_sync_software_updates_permission_denied(self):
        self.set_permissions("mdm.change_softwareupdate")
        response = self.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 403)

    def test_sa_sync_software_updates(self):
        self.set_permissions(
            "mdm.add_softwareupdate",
            "mdm.change_softwareupdate",
            "mdm.delete_softwareupdate",
        )
        response = self.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])

    def test_user_sync_software_updates_unauthorized(self):
        response = self.client.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 401)

    def test_user_sync_software_updates_permission_denied(self):
        self.login("mdm.add_softwareupdate")
        response = self.client.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 403)

    def test_user_sync_software_updates(self):
        self.login(
            "mdm.add_softwareupdate",
            "mdm.change_softwareupdate",
            "mdm.delete_softwareupdate",
        )
        response = self.client.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])
