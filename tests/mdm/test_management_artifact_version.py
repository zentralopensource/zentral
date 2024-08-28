from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.mdm.models import Artifact, DeviceArtifact, TargetArtifact
from .utils import force_artifact, force_blueprint_artifact, force_dep_enrollment_session


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ArtifactVersionManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))

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

    # artifact version

    def test_artifact_version_redirect(self):
        artifact, (profile_av,) = force_artifact()
        self._login_redirect(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))

    def test_artifact_version_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 403)

    def test_profile_artifact_version_get_no_perms_no_links(self):
        artifact, (profile_av,) = force_artifact()
        self._login("mdm.view_artifactversion")
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, profile_av.profile.payload_identifier)
        self.assertContains(response, reverse("mdm:download_profile", args=(profile_av.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk,)))
        self.assertNotContains(response, reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk,)))

    def test_enterprise_app_artifact_version_get_no_perms_no_links(self):
        artifact, (app_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self._login("mdm.view_artifactversion")
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, app_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, reverse("mdm:download_enterprise_app", args=(app_av.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, app_av.pk,)))
        self.assertNotContains(response, reverse("mdm:update_artifact_version", args=(artifact.pk, app_av.pk,)))

    def test_artifact_version_get_delete_perm_link(self):
        artifact, (profile_av,) = force_artifact()
        self.assertTrue(profile_av.can_be_deleted())
        self._login("mdm.view_artifactversion", "mdm.delete_artifactversion")
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        self.assertContains(response, reverse("mdm:download_profile", args=(profile_av.pk,)))
        self.assertContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk,)))
        self.assertNotContains(response, reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk,)))

    def test_artifact_version_get_change_perm_link(self):
        artifact, (profile_av,) = force_artifact()
        self._login("mdm.view_artifactversion", "mdm.change_artifactversion")
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        self.assertContains(response, reverse("mdm:download_profile", args=(profile_av.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk,)))
        self.assertContains(response, reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk,)))

    def test_artifact_version_get_cannot_be_deleted(self):
        _, artifact, (profile_av,) = force_blueprint_artifact()
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.assertFalse(profile_av.can_be_deleted())
        self._login("mdm.view_artifactversion", "mdm.delete_artifactversion")
        response = self.client.get(reverse("mdm:artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk,)))

    # update artifact version

    def test_update_artifact_version_redirect(self):
        artifact, (profile_av,) = force_artifact()
        self._login_redirect(reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk)))

    def test_update_artifact_version_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_artifact_version_get(self):
        artifact, (profile_av,) = force_artifact()
        self._login("mdm.change_artifactversion")
        response = self.client.get(reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_form.html")
        self.assertContains(response, f"Update artifact version v{profile_av.version}")
        self.assertContains(response, artifact.name)

    def test_update_artifact_version_post(self):
        blueprint_artifact, artifact, (profile_av,) = force_blueprint_artifact()
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(len(serialized_artifact["versions"]), 1)
        serialized_artifact_version = serialized_artifact["versions"][0]
        self.assertEqual(serialized_artifact_version["pk"], str(profile_av.pk))
        self.assertEqual(serialized_artifact_version["shard_modulo"], 100)
        self.assertEqual(serialized_artifact_version["default_shard"], 100)
        self.assertTrue(serialized_artifact_version["macos"])
        self.assertIsNone(serialized_artifact_version["macos_min_version"])
        self.assertEqual(serialized_artifact_version["excluded_tags"], [])
        self.assertEqual(serialized_artifact_version["tag_shards"], {})
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        self._login("mdm.change_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:update_artifact_version", args=(artifact.pk, profile_av.pk)),
                                    {"macos": "on",
                                     "macos_min_version": "13.3.1",
                                     "excluded_tags": [excluded_tag.pk],
                                     "shard_modulo": 84,
                                     "default_shard": 0,
                                     f"tag-shard-{shard_tag.pk}": 42},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        profile_av2 = response.context["object"]
        self.assertEqual(profile_av2, profile_av)
        blueprint_artifact.blueprint.refresh_from_db()
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(len(serialized_artifact["versions"]), 1)
        serialized_artifact_version = serialized_artifact["versions"][0]
        self.assertEqual(serialized_artifact_version["pk"], str(profile_av.pk))
        self.assertEqual(serialized_artifact_version["shard_modulo"], 84)
        self.assertEqual(serialized_artifact_version["default_shard"], 0)
        self.assertTrue(serialized_artifact_version["macos"])
        self.assertEqual(serialized_artifact_version["macos_min_version"], [13, 3, 1])
        self.assertEqual(serialized_artifact_version["excluded_tags"], [excluded_tag.pk])
        self.assertEqual(serialized_artifact_version["tag_shards"], {str(shard_tag.pk): 42})

    # delete artifact version

    def test_delete_artifact_version_redirect(self):
        artifact, (profile_av,) = force_artifact()
        self._login_redirect(reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk)))

    def test_delete_artifact_version_permission_denied(self):
        artifact, (profile_av,) = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_artifact_version_cannot_be_deleted(self):
        _, artifact, (profile_av,) = force_blueprint_artifact()
        session, _, _ = force_dep_enrollment_session(self.mbu, completed=True)
        DeviceArtifact.objects.create(
            enrolled_device=session.enrolled_device,
            artifact_version=profile_av,
            status=TargetArtifact.Status.INSTALLED
        )
        self.assertFalse(profile_av.can_be_deleted())
        self._login("mdm.delete_artifactversion", "mdm.view_artifact")
        response = self.client.get(reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 404)

    def test_delete_artifact_version_get(self):
        artifact, (profile_av,) = force_artifact()
        self._login("mdm.delete_artifactversion")
        response = self.client.get(reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"Delete artifact version v{profile_av.version}")

    def test_delete_artifact_version_post(self):
        blueprint_artifact, artifact, (profile_av1, profile_av2) = force_blueprint_artifact(version_count=2)
        blueprint = blueprint_artifact.blueprint
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 2)
        self._login("mdm.delete_artifactversion", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av1.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertNotContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av1.pk)))
        self.assertContains(response, reverse("mdm:delete_artifact_version", args=(artifact.pk, profile_av2.pk)))
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.serialized_artifacts[str(artifact.pk)]["versions"]), 1)
