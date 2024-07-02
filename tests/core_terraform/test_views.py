from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from .utils import force_state, force_state_version


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class TerraformViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
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
        self.client.force_login(self.user)

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("terraform:index"))

    def test_index_permission_denied(self):
        self._login('terraform.view_stateversion')
        response = self.client.get(reverse("terraform:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        state = force_state()
        self._login('terraform.view_state')
        response = self.client.get(reverse("terraform:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "terraform/index.html")
        self.assertContains(response, "TF state (1)")
        self.assertContains(response, state.slug)

    # state

    def test_state_redirect(self):
        state = force_state()
        self._login_redirect(state.get_absolute_url())

    def test_state_permission_denied(self):
        state = force_state()
        self._login("terraform.view_stateversion")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_state_no_versions(self):
        state = force_state_version().state
        self._login("terraform.view_state")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, state.slug)
        self.assertNotContains(response, "1 Version")

    def test_state_versions(self):
        state = force_state_version().state
        self._login("terraform.view_state", "terraform.view_stateversion")
        response = self.client.get(state.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, state.slug)
        self.assertNotContains(response, "1 Version")
