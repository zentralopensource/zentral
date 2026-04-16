from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase


class SoftwareUpdatesAPIViewsTestCase(TestCase, LoginCase, RequestCase):
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
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

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

    def test_user_sync_software_updates_with_perms_unauthorized(self):
        self.login(
            "mdm.add_softwareupdate",
            "mdm.change_softwareupdate",
            "mdm.delete_softwareupdate",
        )
        response = self.client.post(reverse("mdm_api:sync_software_updates"))
        self.assertEqual(response.status_code, 401)
