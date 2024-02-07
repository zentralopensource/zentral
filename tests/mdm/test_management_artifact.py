from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.models import Artifact, ArtifactVersion, Platform
from .utils import force_artifact, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ArtifactManagementViewsTestCase(TestCase):
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

    # artifacts

    def test_artifacts_redirect(self):
        self._login_redirect(reverse("mdm:artifacts"))

    def test_artifacts_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:artifacts"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.mdm.views.management.ArtifactListView.get_paginate_by")
    def test_artifacts(self, get_paginate_by):
        get_paginate_by.return_value = 1
        artifacts = sorted([force_artifact()[0] for _ in range(3)], key=lambda a: a.name.lower())
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:artifacts"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_list.html")
        self.assertNotContains(response, artifacts[0].name)
        self.assertContains(response, artifacts[1].name)
        self.assertNotContains(response, artifacts[2].name)
        self.assertContains(response, "Artifacts (3)")
        self.assertContains(response, "page 2 of 3")

    def test_artifacts_search(self):
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:artifacts"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_list.html")
        self.assertContains(response, "Artifacts (0)")
        self.assertNotContains(response, "We didn't find any item related to your search")
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        blueprint = blueprint_artifact.blueprint
        _, artifact2, _ = force_blueprint_artifact(blueprint=blueprint)
        artifact3, _ = force_artifact()
        response = self.client.get(
            reverse("mdm:artifacts"),
            {"blueprint": blueprint.pk},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_list.html")
        self.assertContains(response, "Artifacts (2)")
        self.assertContains(response, artifact.name)
        self.assertContains(response, artifact2.name)
        self.assertNotContains(response, artifact3.name)
        self.assertContains(response, "page 1 of 1")
        response = self.client.get(
            reverse("mdm:artifacts"),
            {"q": "does not exists"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_list.html")
        self.assertContains(response, "Artifacts (0)")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("mdm:artifacts") + '">all the items')

    def test_artifacts_search_redirect(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.view_artifact")
        response = self.client.get(
            reverse("mdm:artifacts"),
            {"artifact_type": artifact.type,
             "blueprint": blueprint_artifact.blueprint.pk,
             "channel": artifact.channel,
             "platform": artifact.platforms[0],
             "q": artifact.name},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertEqual(response.context["object"], artifact)

    # artifact

    def test_artifact_redirect(self):
        artifact, _ = force_artifact()
        self._login_redirect(reverse("mdm:artifact", args=(artifact.pk,)))

    def test_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_artifact_get_no_perms_no_delete_no_perms_to_upgrade(self):
        artifact, _ = force_artifact()
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, artifact.name)
        self.assertNotContains(response, reverse("mdm:delete_artifact", args=(artifact.pk,)))
        self.assertNotContains(response, reverse("mdm:upgrade_profile", args=(artifact.pk,)))
        self.assertContains(response, "Blueprints (0)")
        self.assertNotContains(response, reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)))

    def test_artifact_with_delete_ba_links(self):
        artifact, _ = force_artifact()
        self._login("mdm.view_artifact", "mdm.delete_artifact", "mdm.add_blueprintartifact")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, reverse("mdm:delete_artifact", args=(artifact.pk,)))
        self.assertContains(response, "Blueprints (0)")
        self.assertContains(response, reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)))

    def test_artifact_get_cannot_be_deleted(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.view_artifact", "mdm.delete_artifact")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, artifact.name)
        self.assertContains(response, blueprint_artifact.blueprint.name)
        self.assertNotContains(response, reverse("mdm:delete_artifact", args=(artifact.pk,)))

    def test_artifact_download_profile(self):
        artifact_one, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP,)
        artifact_two, _ = force_artifact()
        self._login("mdm.view_artifact", "mdm.view_artifactversion")
        for artifact in [artifact_one, artifact_two]:
            response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "mdm/artifact_detail.html")
            self.assertContains(response, artifact.name)
            av = ArtifactVersion.objects.filter(artifact=artifact).order_by("-version").first().pk
            if artifact.type == Artifact.Type.PROFILE:
                self.assertContains(response, reverse("mdm:download_profile", args=(av,)))
            else:
                self.assertNotContains(response, reverse("mdm:download_profile", args=(av,)))

    def test_artifact_cannot_download_profile(self):
        artifact, _ = force_artifact()
        self._login("mdm.view_artifact",)
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, artifact.name)
        av = ArtifactVersion.objects.filter(artifact=artifact).order_by("-version").first().pk
        self.assertNotContains(response, reverse("mdm:download_profile", args=(av,)))

    def test_artifact_get_enterprise_app_upgrade_link(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self._login("mdm.view_artifact", "mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)))

    def test_artifact_get_profile_upgrade_link(self):
        artifact, _ = force_artifact()
        self._login("mdm.view_artifact", "mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, reverse("mdm:upgrade_profile", args=(artifact.pk,)))

    def test_artifact_get_store_app_upgrade_link(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self._login("mdm.view_artifact", "mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, reverse("mdm:upgrade_store_app", args=(artifact.pk,)))

    # update artifact

    def test_update_artifact_redirect(self):
        artifact, _ = force_artifact()
        self._login_redirect(reverse("mdm:update_artifact", args=(artifact.pk,)))

    def test_update_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:update_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_artifact_get(self):
        artifact, _ = force_artifact()
        self._login("mdm.change_artifact")
        response = self.client.get(reverse("mdm:update_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_form.html")
        self.assertContains(response, f"Update {artifact.name}")
        self.assertContains(response, artifact.name)

    def test_update_artifact_post(self):
        required_artifact, _ = force_artifact()
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self.assertTrue(artifact.auto_update)
        self.assertEqual(artifact.platforms, [Platform.MACOS])
        self.assertEqual(artifact.requires.count(), 0)
        self.assertFalse(artifact.install_during_setup_assistant)
        self.assertTrue(artifact.auto_update)
        self.assertEqual(artifact.reinstall_interval, 0)
        self.assertEqual(Artifact.ReinstallOnOSUpdate(artifact.reinstall_on_os_update),
                         Artifact.ReinstallOnOSUpdate.NO)
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(serialized_artifact["requires"], [])
        self.assertFalse(serialized_artifact["install_during_setup_assistant"])
        self.assertTrue(serialized_artifact["auto_update"])
        self._login("mdm.change_artifact", "mdm.view_artifact")
        new_name = get_random_string(12)
        response = self.client.post(reverse("mdm:update_artifact", args=(artifact.pk,)),
                                    {"name": new_name,
                                     "requires": [required_artifact.pk],
                                     "platforms": [Platform.MACOS.value, Platform.IOS.value],
                                     "auto_update": False,
                                     "install_during_setup_assistant": True,
                                     "reinstall_interval": 90,
                                     "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.PATCH.value},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact2 = response.context["object"]
        self.assertEqual(artifact2, artifact)
        self.assertEqual(artifact2.name, new_name)
        self.assertEqual(set(artifact2.platforms), set([Platform.MACOS, Platform.IOS]))
        self.assertEqual(artifact2.requires.count(), 1)
        self.assertEqual(artifact2.requires.first(), required_artifact)
        self.assertTrue(artifact2.install_during_setup_assistant)
        self.assertFalse(artifact2.auto_update)
        self.assertEqual(artifact2.reinstall_interval, 90)
        self.assertEqual(Artifact.ReinstallOnOSUpdate(artifact2.reinstall_on_os_update),
                         Artifact.ReinstallOnOSUpdate.PATCH)
        blueprint_artifact.blueprint.refresh_from_db()
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(required_artifact.pk), str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(serialized_artifact["requires"], [str(required_artifact.pk)])
        self.assertTrue(serialized_artifact["install_during_setup_assistant"])
        self.assertFalse(serialized_artifact["auto_update"])

    def test_update_store_app_artifact_no_platforms_change(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self.assertEqual(artifact.platforms, [Platform.MACOS])
        self._login("mdm.change_artifact", "mdm.view_artifact")
        new_name = get_random_string(12)
        response = self.client.post(reverse("mdm:update_artifact", args=(artifact.pk,)),
                                    {"name": new_name,
                                     "platforms": [Platform.MACOS.value, Platform.IOS.value],
                                     "auto_update": True,
                                     "install_during_setup_assistant": False,
                                     "reinstall_interval": 0,
                                     "reinstall_on_os_update": Artifact.ReinstallOnOSUpdate.NO.value},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact2 = response.context["object"]
        self.assertEqual(artifact2, artifact)
        self.assertEqual(artifact2.name, new_name)
        # cannot change the platforms on a store app
        self.assertEqual(set(artifact2.platforms), set([Platform.MACOS]))

    # delete artifact

    def test_delete_artifact_redirect(self):
        artifact, _ = force_artifact()
        self._login_redirect(reverse("mdm:delete_artifact", args=(artifact.pk,)))

    def test_delete_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:delete_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_artifact_cannot_be_deleted(self):
        _, artifact, _ = force_blueprint_artifact()
        self._login("mdm.delete_artifact", "mdm.view_artifact")
        response = self.client.get(reverse("mdm:delete_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_artifact_get(self):
        artifact, _ = force_artifact()
        self._login("mdm.delete_artifact")
        response = self.client.get(reverse("mdm:delete_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"Delete {artifact.name}")

    def test_delete_artifact_post(self):
        artifact, _ = force_artifact()
        self._login("mdm.delete_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:delete_artifact", args=(artifact.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_list.html")
        self.assertNotContains(response, artifact.name)
