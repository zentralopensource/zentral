from django.contrib.auth.models import Group
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from .utils import force_state, force_state_version


class TerraformViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "terraform"

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login('terraform.add_state')
        response = self.client.get(reverse("terraform:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        state = force_state()
        self.login('terraform.view_state')
        response = self.client.get(reverse("terraform:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "terraform/index.html")
        self.assertContains(response, "TF state (1)")
        self.assertContains(response, state.slug)

    # state

    def test_state_redirect(self):
        state = force_state()
        self.login_redirect("state", state.pk)

    def test_state_permission_denied(self):
        state = force_state()
        self.login("terraform.add_state")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_state_no_versions(self):
        state = force_state_version().state
        self.login("terraform.view_state")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, state.slug)
        self.assertNotContains(response, "1 Version")

    def test_state_versions(self):
        state = force_state_version().state
        self.login("terraform.view_state")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, state.slug)
        self.assertNotContains(response, "1 Version")
