from accounts.models import User
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from typing_extensions import override

from tests.core_probes.utils import force_action
from tests.zentral_test_utils.login_case import LoginCase
from zentral.utils.provisioning import provision


class ActionViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        # user
        cls.user = User.objects.create_user(
            "godzilla", "godzilla@zentral.io", get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    @override
    def _get_user(self):
        return self.user

    @override
    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "probes"

    # action details

    def test_detail_action_redirect(self):
        action = force_action()
        self.login_redirect("action", str(action.pk))

    def test_detail_action_permission_denied(self):
        action = force_action()
        self.login()
        response = self.client.get(reverse("probes:action", args=(str(action.pk),)))
        self.assertEqual(response.status_code, 403)

    def test_detail_action_get(self):
        action = force_action(
            backend_kwargs={
                "url": "https://www.example.com/post",
                "headers": [{"name": "Authorization", "value": "secret"}],
            }
        )
        self.login("probes.view_action")
        response = self.client.get(reverse("probes:action", args=(str(action.pk),)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/action_detail.html")
        self.assertContains(response, "Action")
        self.assertContains(response, action.name)
        self.assertContains(response, "value_hash")

    # action list

    def test_list_redirect(self):
        self.login_redirect("actions")

    def test_list_permission_denied(self):
        self.login()
        response = self.client.get(reverse("probes:actions"))
        self.assertEqual(response.status_code, 403)

    def test_list_get(self):
        action = force_action()
        self.login("probes.view_action")
        response = self.client.get(reverse("probes:actions"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/action_list.html")
        self.assertContains(response, "Action")
        self.assertContains(response, action.name)
