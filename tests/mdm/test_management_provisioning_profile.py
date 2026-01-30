from io import BytesIO
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.db import IntegrityError
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.models import Artifact, Channel
from tests.zentral_test_utils.login_case import LoginCase
from .utils import (build_provisioning_profile_content, build_provisioning_profile_file,
                    force_artifact, force_blueprint_artifact)


class ProvisioningProfileManagementViewsTestCase(LoginCase, TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    # upload profile GET

    def test_upload_provisioning_profile_get_redirect(self):
        self.login_redirect("upload_provisioning_profile")

    def test_upload_provisioning_profile_get_permission_denied(self):
        self.login()
        self.permission_denied("upload_provisioning_profile")

    def test_upload_provisioning_profile_get(self):
        self.login("mdm.add_artifact")
        response = self.client.get(self.build_url("upload_provisioning_profile"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/provisioningprofile_form.html")

    # upload profile POST

    def test_upload_provisioning_profile_post_redirect(self):
        source_file = build_provisioning_profile_file()
        self.login_redirect("upload_provisioning_profile", data={"source_file": source_file})

    def test_upload_provisioning_profile_post_permission_denied(self):
        source_file = build_provisioning_profile_file()
        self.login()
        self.permission_denied("upload_provisioning_profile", data={"source_file": source_file})

    def test_upload_provisioning_profile_post_empty_file(self):
        self.login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(self.build_url("upload_provisioning_profile"),
                                    {"source_file": BytesIO(b"")},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/provisioningprofile_form.html")
        self.assertFormError(response.context["form"], "source_file", "The submitted file is empty.")

    def test_upload_provisioning_profile_post_not_signed(self):
        source_file = build_provisioning_profile_file(signed=False)
        self.login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(self.build_url("upload_provisioning_profile"),
                                    {"source_file": source_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/provisioningprofile_form.html")
        self.assertFormError(response.context["form"], "source_file", "Could not verify signature")

    def test_upload_provisioning_profile_post_invalid_signed_data(self):
        source_file = build_provisioning_profile_file(raw_content=b"-")
        self.login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(self.build_url("upload_provisioning_profile"),
                                    {"source_file": source_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/provisioningprofile_form.html")
        self.assertFormError(response.context["form"], "source_file", "Invalid signed data")

    def test_upload_provisioning_profile_post_missing_uuid(self):
        source_file = build_provisioning_profile_file(content={})
        self.login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(self.build_url("upload_provisioning_profile"),
                                    {"source_file": source_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/provisioningprofile_form.html")
        self.assertFormError(response.context["form"], "source_file", "Could not read provisioning profile UUID")

    @patch("zentral.contrib.mdm.forms.Artifact.objects.create")
    def test_upload_provisioning_profile_post_unique_name_error(self, artifact_create):
        artifact_create.side_effect = IntegrityError("Boom")
        source_file = build_provisioning_profile_file()
        self.login("mdm.add_artifact", "mdm.view_artifact")
        with self.assertRaises(RuntimeError) as cm:
            self.client.post(self.build_url("upload_provisioning_profile"),
                             {"source_file": source_file},
                             follow=True)
        self.assertEqual(cm.exception.args[0], "Could not find unique name for artifact")

    def test_upload_provisioning_profile_post(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE, version_count=0)
        provisioning_profile_content = build_provisioning_profile_content(name=artifact.name)  # name collision
        source_file = build_provisioning_profile_file(content=provisioning_profile_content)
        self.login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(self.build_url("upload_provisioning_profile"),
                                    {"source_file": source_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact created")
        self.assertContains(response, provisioning_profile_content["AppIDName"])
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.PROVISIONING_PROFILE)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(artifact.name, provisioning_profile_content["Name"] + " (1)")
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        provisioning_profile = artifact_version.provisioning_profile
        self.assertEqual(str(provisioning_profile.uuid), provisioning_profile_content["UUID"])
        self.assertEqual(provisioning_profile.name, provisioning_profile_content["Name"])
        self.assertEqual(provisioning_profile.get_content(), provisioning_profile_content)

    # upgrade profile GET

    def test_upgrade_provisioning_profile_get_login_redirect(self):
        artifact, _ = force_artifact(version_count=0, artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login_redirect("upgrade_provisioning_profile", artifact.pk)

    def test_upgrade_provisioning_profile_get_permission_denied(self):
        artifact, _ = force_artifact(version_count=0, artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login()
        self.permission_denied("upgrade_provisioning_profile", artifact.pk)

    def test_upgrade_provisioning_profile_get(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login("mdm.add_artifactversion")
        response = self.client.get(self.build_url("upgrade_provisioning_profile", artifact.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade profile POST

    def test_upgrade_provisioning_profile_post_same_payload(self):
        artifact, (av,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login("mdm.add_artifactversion", "mdm.view_artifactversion")
        source_file = BytesIO(av.provisioning_profile.source)
        source_file.name = "yolo.provisionprofile"
        response = self.client.post(self.build_url("upgrade_provisioning_profile", artifact.pk),
                                    {"source_file": source_file},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["object_form"], "source_file",
                             "This provisioning profile is not different from the latest one.")

    def test_upgrade_provisioning_profile_post(self):
        bpa, a, (av,) = force_blueprint_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        blueprint = bpa.blueprint
        artifact_pk = str(a.pk)
        first_provisioning_profile_pk = str(av.pk)
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            list(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            [first_provisioning_profile_pk]
        )
        provisioning_profile_content = build_provisioning_profile_content()
        source_file = build_provisioning_profile_file(content=provisioning_profile_content)
        self.login("mdm.add_artifactversion", "mdm.view_artifactversion")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        response = self.client.post(self.build_url("upgrade_provisioning_profile", a.pk),
                                    {"source_file": source_file,
                                     "default_shard": 7,
                                     "shard_modulo": 99,
                                     "macos": "on",
                                     "macos_min_version": "14",
                                     "excluded_tags": [excluded_tag.id],
                                     f"tag-shard-{shard_tag.pk}": 99},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        artifact_version = response.context["object"]
        self.assertEqual(a, artifact_version.artifact)
        self.assertEqual(a.artifactversion_set.count(), 2)
        self.assertEqual(artifact_version.version, 2)
        self.assertTrue(artifact_version.macos)
        self.assertEqual(artifact_version.macos_min_version, "14")
        self.assertEqual(list(artifact_version.excluded_tags.all()), [excluded_tag])
        self.assertEqual(artifact_version.item_tags.count(), 1)
        av_tag = artifact_version.item_tags.first()
        self.assertEqual(av_tag.tag, shard_tag)
        self.assertEqual(av_tag.shard, 99)
        provisioning_profile = artifact_version.provisioning_profile
        self.assertEqual(str(provisioning_profile.uuid), provisioning_profile_content["UUID"])
        self.assertEqual(provisioning_profile.name, provisioning_profile_content["Name"])
        self.assertEqual(provisioning_profile.get_content(), provisioning_profile_content)
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            {first_provisioning_profile_pk, str(artifact_version.pk)}
        )

    # download profile

    def test_download_provisioning_profile_login_redirect(self):
        _, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login_redirect("download_provisioning_profile", artifact_version.pk)

    def test_download_provisioning_profile_permission_denied(self):
        _, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login()
        self.permission_denied("download_provisioning_profile", artifact_version.pk)

    def test_download_provisioning_profile(self):
        _, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.PROVISIONING_PROFILE)
        self.login("mdm.view_artifactversion")
        response = self.client.get(self.build_url("download_provisioning_profile", artifact_version.pk))
        self.assertEqual(response.status_code, 200)
        provisioning_profile = artifact_version.provisioning_profile
        self.assertEqual(
            response["Content-Disposition"],
            'attachment; '
            f'filename="{provisioning_profile.name.lower()}_{provisioning_profile.pk}_v1.provisionprofile"'
        )
        self.assertEqual(b"".join(response.streaming_content), provisioning_profile.source)
