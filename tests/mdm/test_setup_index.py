from functools import reduce
import io
import operator
import zipfile
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from .utils import force_artifact, force_blueprint, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SetupIndexViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

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
        self._login_redirect(reverse("mdm:index"))

    def test_index_locations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_view_artifact_perm(self):
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:index"))
        self.assertTemplateUsed(response, "mdm/index.html")
        self.assertContains(response, "Overview")
        self.assertContains(response, reverse("mdm:artifacts"))
        self.assertNotContains(response, reverse("mdm:blueprints"))
        self.assertNotContains(response, reverse("mdm:terraform_export"))

    def test_index_view_blueprint_perm(self):
        self._login("mdm.view_blueprint")
        response = self.client.get(reverse("mdm:index"))
        self.assertTemplateUsed(response, "mdm/index.html")
        self.assertContains(response, "Overview")
        self.assertNotContains(response, reverse("mdm:artifacts"))
        self.assertContains(response, reverse("mdm:blueprints"))
        self.assertContains(response, reverse("mdm:terraform_export"))

    # terraform export

    def test_terraform_export_redirect(self):
        self._login_redirect(reverse("mdm:terraform_export"))

    def test_terraform_export_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:terraform_export"))
        self.assertEqual(response.status_code, 403)

    def test_terraform_export(self):
        self._login("mdm.view_blueprint")
        blueprint = force_blueprint()
        required_artifact, _ = force_artifact()
        blueprint_artifact, artifact, _ = force_blueprint_artifact(blueprint=blueprint)
        artifact.requires.add(required_artifact)
        response = self.client.get(reverse("mdm:terraform_export"))
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(response.content), mode="r") as zf:
            with zf.open("mdm_blueprints.tf") as btf:
                self.assertEqual(
                    btf.read().decode("utf-8"),
                    f'resource "zentral_mdm_blueprint" "blueprint{blueprint.pk}" {{\n'
                    f'  name = "{blueprint.name}"\n'
                    '}\n\n'
                    f'resource "zentral_mdm_blueprint_artifact" "blueprintartifact{blueprint_artifact.pk}" {{\n'
                    f'  blueprint_id = zentral_mdm_blueprint.blueprint{blueprint.pk}.id\n'
                    f'  artifact_id  = zentral_mdm_artifact.artifact{artifact.pk}.id\n'
                    '  macos        = true\n'
                    '}\n\n'
                )
            with zf.open("mdm_artifacts.tf") as atf:
                self.assertEqual(
                    atf.read().decode("utf-8"),
                    f'resource "zentral_mdm_artifact" "artifact{required_artifact.pk}" {{\n'
                    f'  name      = "{required_artifact.name}"\n'
                    '  type      = "Profile"\n'
                    '  channel   = "Device"\n'
                    '  platforms = ["macOS"]\n'
                    '}\n\n'
                    f'resource "zentral_mdm_artifact" "artifact{artifact.pk}" {{\n'
                    f'  name      = "{artifact.name}"\n'
                    '  type      = "Profile"\n'
                    '  channel   = "Device"\n'
                    '  platforms = ["macOS"]\n'
                    f'  requires  = [zentral_mdm_artifact.artifact{required_artifact.pk}.id]\n'
                    '}\n\n'
                )
