from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import BlueprintArtifact, BlueprintArtifactTag
from .utils import force_artifact, force_blueprint, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class BlueprintArtifactManagementViewsTestCase(TestCase):
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

    # create

    def test_create_blueprint_artifact_redirect(self):
        artifact, _ = force_artifact()
        self._login_redirect(reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)))

    def test_create_blueprint_artifact_permission_denied(self):
        artifact, _ = force_artifact()
        self._login()
        response = self.client.get(reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_blueprint_artifact_get(self):
        artifact, _ = force_artifact()
        self._login("mdm.add_blueprintartifact")
        response = self.client.get(reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")

    def test_create_blueprint_artifact_happy_minimal_path(self):
        artifact, _ = force_artifact()
        blueprint = force_blueprint()
        self.assertEqual(blueprint.serialized_artifacts, {})
        self._login("mdm.add_blueprintartifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:create_blueprint_artifact", args=(artifact.pk,)),
            {"blueprint": blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 5,
             "macos": "on"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, blueprint.name)
        blueprint_artifact = BlueprintArtifact.objects.get(blueprint=blueprint, artifact=artifact)
        self.assertEqual(blueprint_artifact.shard_modulo, 10)
        self.assertEqual(blueprint_artifact.default_shard, 5)
        self.assertTrue(blueprint_artifact.macos)
        blueprint.refresh_from_db()
        self.assertEqual(set(blueprint.serialized_artifacts.keys()), set([str(artifact.pk)]))

    # update

    def test_update_blueprint_artifact_redirect(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login_redirect(reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))

    def test_update_blueprint_artifact_permission_denied(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.add_blueprintartifact")
        response = self.client.get(reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_blueprint_artifact_get(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.change_blueprintartifact")
        response = self.client.get(reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")

    def test_update_blueprint_artifact_at_least_one_platform_error(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.change_blueprintartifact")
        response = self.client.post(
            reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            {"blueprint": blueprint_artifact.blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 5}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")
        self.assertFormError(response.context["form"], None, ["You need to activate at least one platform"])

    def test_update_blueprint_artifact_platform_not_available(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.change_blueprintartifact")
        response = self.client.post(
            reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            {"blueprint": blueprint_artifact.blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 5,
             "ipados": "on"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")
        self.assertFormError(response.context["form"], "ipados", ["Platform not available for this artifact"])

    def test_update_blueprint_artifact_default_shard_gt_shard_modulo(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.change_blueprintartifact")
        response = self.client.post(
            reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            {"blueprint": blueprint_artifact.blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 11,  # > shard modulo, error
             "macos": "on"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")
        self.assertFormError(response.context["form"],
                             "default_shard", ["Must be less than or equal to the shard modulo"])

    def test_update_blueprint_artifact_excluded_tags_tag_shard_conflict(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        tag = Tag.objects.create(name=get_random_string(12))
        self._login("mdm.change_blueprintartifact")
        response = self.client.post(
            reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            {"blueprint": blueprint_artifact.blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 1,
             "excluded_tags": [tag.pk],  # conflict with tag shard
             f"tag-shard-{tag.pk}": 5,
             "macos": "on"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_form.html")
        self.assertFormError(response.context["form"], "excluded_tags", [f"Conflict with {tag} shard"])

    def test_update_blueprint_artifact(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        prev_tag = Tag.objects.create(name=get_random_string(12))
        BlueprintArtifactTag.objects.create(blueprint_artifact=blueprint_artifact, tag=prev_tag, shard=5)
        update_blueprint_serialized_artifacts(blueprint_artifact.blueprint)
        self.assertEqual(blueprint_artifact.excluded_tags.count(), 0)
        self.assertEqual(blueprint_artifact.macos_min_version, "")
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(serialized_artifact["macos_min_version"], None)
        self.assertEqual(serialized_artifact["shard_modulo"], 100)
        self.assertEqual(serialized_artifact["default_shard"], 100)
        self.assertEqual(serialized_artifact["excluded_tags"], [])
        self.assertEqual(serialized_artifact["tag_shards"], {str(prev_tag.pk): 5})
        next_tag = Tag.objects.create(name=get_random_string(12))
        excl_tag = Tag.objects.create(name=get_random_string(12))
        self._login("mdm.change_blueprintartifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:update_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            {"blueprint": blueprint_artifact.blueprint.pk,
             "shard_modulo": 10,
             "default_shard": 1,
             "excluded_tags": [excl_tag.pk],
             f"tag-shard-{next_tag.pk}": 6,
             "macos": "on",
             "macos_min_version": "10.15.0"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        blueprint_artifact.refresh_from_db()
        serialized_artifacts = blueprint_artifact.blueprint.serialized_artifacts
        self.assertEqual(set(serialized_artifacts.keys()), set([str(artifact.pk)]))
        serialized_artifact = serialized_artifacts[str(artifact.pk)]
        self.assertEqual(serialized_artifact["macos_min_version"], [10, 15, 0])
        self.assertEqual(serialized_artifact["shard_modulo"], 10)
        self.assertEqual(serialized_artifact["default_shard"], 1)
        self.assertEqual(serialized_artifact["excluded_tags"], [excl_tag.pk])
        self.assertEqual(serialized_artifact["tag_shards"], {str(next_tag.pk): 6})

    # delete

    def test_delete_blueprint_artifact_redirect(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login_redirect(reverse("mdm:delete_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))

    def test_delete_blueprint_artifact_permission_denied(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:delete_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_blueprint_artifact_get(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self._login("mdm.delete_blueprintartifact")
        response = self.client.get(reverse("mdm:delete_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/blueprintartifact_confirm_delete.html")
        self.assertContains(response, f"Remove {artifact} from {blueprint_artifact.blueprint}")

    def test_delete_blueprint_artifact(self):
        blueprint_artifact, artifact, _ = force_blueprint_artifact()
        self.assertEqual(artifact.blueprintartifact_set.count(), 1)
        blueprint = blueprint_artifact.blueprint
        self._login("mdm.delete_blueprintartifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:delete_blueprint_artifact", args=(artifact.pk, blueprint_artifact.pk)),
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertEqual(response.context["object"], artifact)
        self.assertNotContains(response, blueprint.name)
        self.assertEqual(artifact.blueprintartifact_set.count(), 0)
