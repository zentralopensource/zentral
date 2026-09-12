import plistlib
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.mdm.crypto import verify_signed_payload


class SetupIndexViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_locations_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_view_artifact_perm(self):
        self.login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:index"))
        self.assertTemplateUsed(response, "mdm/index.html")
        self.assertContains(response, "Overview")
        self.assertContains(response, reverse("mdm:artifacts"))
        self.assertNotContains(response, reverse("mdm:blueprints"))

    def test_index_view_blueprint_perm(self):
        self.login("mdm.view_blueprint")
        response = self.client.get(reverse("mdm:index"))
        self.assertTemplateUsed(response, "mdm/index.html")
        self.assertContains(response, "Overview")
        self.assertNotContains(response, reverse("mdm:artifacts"))
        self.assertContains(response, reverse("mdm:blueprints"))

    # root CA

    def test_root_ca_redirect(self):
        self.login_redirect("root_ca")

    def test_root_ca_permission_denied(self):
        self.login()
        response = self.client.get(reverse("mdm:root_ca"))
        self.assertEqual(response.status_code, 403)

    def test_root_ca(self):
        self.login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:root_ca"))
        self.assertEqual(response.status_code, 200)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(len(payload["PayloadContent"]), 1)
        self.assertEqual(payload["PayloadContent"][0]["PayloadType"], "com.apple.security.pem")
