from functools import reduce
from io import BytesIO
import operator
import os.path
import plistlib
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion,
                                        Blueprint, BlueprintArtifact, Channel, Platform, Profile)
from zentral.utils.payloads import sign_payload


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ProfileManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

    def _login_redirect(self, url, data=None):
        if data:
            func = self.client.post
        else:
            func = self.client.get
        response = func(url, data=data)
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

    def _get_payload(
        self,
        channel=None,
        payload_id=None,
        payload_uuid=None,
        missing_payload_id=False,
        missing_payload_uuid=False,
        payload_scope=None,
    ):
        payload = plistlib.load(
            open(os.path.join(os.path.dirname(__file__),
                              "testdata/test.mobileconfig"),
                 "rb")
        )
        if channel == Channel.DEVICE:
            payload["PayloadScope"] = "System"
        elif channel == Channel.USER:
            payload["PayloadScope"] = "User"
        if payload_id:
            payload["PayloadIdentifier"] = payload_id
        if payload_uuid:
            payload["PayloadUUID"] = payload_uuid
        if missing_payload_id:
            payload.pop("PayloadIdentifier")
        if missing_payload_uuid:
            payload.pop("PayloadUUID")
        if payload_scope:
            payload["PayloadScope"] = payload_scope
        return payload

    def _build_mobileconfig(
        self,
        channel=None,
        payload_uuid=None,
        missing_payload_id=False,
        missing_payload_uuid=False,
        payload_scope=None,
        signed=False
    ):
        payload = self._get_payload(
            channel=channel,
            payload_uuid=payload_uuid,
            missing_payload_id=missing_payload_id,
            missing_payload_uuid=missing_payload_uuid,
            payload_scope=payload_scope,
        )
        data = plistlib.dumps(payload)
        if signed:
            data = sign_payload(data)
        mobileconfig = BytesIO(data)
        mobileconfig.name = "test.mobileconfig"
        return mobileconfig

    def _force_profile(self, channel=None, payload_id=None):
        payload = self._get_payload(channel=channel, payload_id=payload_id)
        artifact = Artifact.objects.create(
            name=payload["PayloadDisplayName"],
            type=Artifact.Type.PROFILE,
            channel=channel if channel else Channel.USER,
            platforms=[Platform.MACOS],
            auto_update=True,
        )
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=1, macos=True,
        )
        profile = Profile.objects.create(
            artifact_version=artifact_version,
            filename="test.mobileconfig",
            source=plistlib.dumps(payload),
            payload_identifier=payload["PayloadIdentifier"],
            payload_display_name=payload["PayloadDisplayName"],
            payload_description=payload["PayloadDescription"],
        )
        blueprint = Blueprint.objects.create(name=get_random_string(12))
        BlueprintArtifact.objects.get_or_create(
            blueprint=blueprint,
            artifact=artifact,
            defaults={"macos": True},
        )
        update_blueprint_serialized_artifacts(blueprint)
        return blueprint, artifact, profile

    def _force_blueprint(self):
        return Blueprint.objects.create(name=get_random_string(12))

    # upload profile GET

    def test_upload_profile_get_redirect(self):
        self._login_redirect(reverse("mdm:upload_profile"))

    def test_upload_profile_get_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:upload_profile"))
        self.assertEqual(response.status_code, 403)

    def test_upload_profile_get(self):
        self._login("mdm.add_artifact")
        response = self.client.get(reverse("mdm:upload_profile"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")

    # upload profile POST

    def test_upload_profile_post_redirect(self):
        mobileconfig = self._build_mobileconfig()
        self._login_redirect(reverse("mdm:upload_profile"),
                             {"source_file": mobileconfig})

    def test_upload_profile_post_permission_denied(self):
        mobileconfig = self._build_mobileconfig()
        self._login()
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig})
        self.assertEqual(response.status_code, 403)

    def test_upload_profile_post_not_a_plist(self):
        notaplist = BytesIO(b"-")
        notaplist.name = "test.mobileconfig"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": notaplist},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(response, "form", "source_file", "This file is not a plist.")

    def test_upload_profile_post_missing_payload_identifier(self):
        mobileconfig = self._build_mobileconfig(missing_payload_id=True)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(response, "form", "source_file", "Missing PayloadIdentifier.")

    def test_upload_profile_post_missing_payload_uuid(self):
        mobileconfig = self._build_mobileconfig(missing_payload_uuid=True)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(response, "form", "source_file", "Missing PayloadUUID.")

    def test_upload_profile_post_unknown_payload_scope(self):
        mobileconfig = self._build_mobileconfig(payload_scope="HAHA")
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(response, "form", "source_file", "Unknown PayloadScope: HAHA.")

    def test_upload_profile_post(self):
        mobileconfig = self._build_mobileconfig()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact created")
        self.assertContains(response, "com.example.my-profile")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.PROFILE)
        self.assertEqual(artifact.channel, Channel.USER)  # PayloadScope not present → User
        self.assertEqual(artifact.name, "iOS Restrictions")
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        profile = artifact_version.profile
        self.assertEqual(profile.payload_identifier, "com.example.my-profile")
        self.assertEqual(profile.payload_uuid, "8846C027-9F51-4574-9042-33C118F3D43E")
        self.assertEqual(profile.payload_display_name, "iOS Restrictions")
        self.assertEqual(
            profile.payload_description,
            "Auto-date&time, no in-app purchase, for test purpose blocked: no Siri no siri suggestions, no AirPrint"
        )

    def test_upload_profile_post_signed(self):
        mobileconfig = self._build_mobileconfig(signed=True)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact created")
        self.assertContains(response, "com.example.my-profile")

    def test_upload_profile_post_existing_profile(self):
        self._force_profile()
        mobileconfig = self._build_mobileconfig()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "iOS Restrictions (1)")
        artifact = response.context["object"]
        self.assertEqual(artifact.name, "iOS Restrictions (1)")

    # upgrade profile GET

    def test_upgrade_profile_get_login_redirect(self):
        _, artifact, _ = self._force_profile()
        self._login_redirect(reverse("mdm:upgrade_profile", args=(artifact.pk,)))

    def test_upgrade_profile_get_permission_denied(self):
        _, artifact, _ = self._force_profile()
        self._login()
        response = self.client.get(reverse("mdm:upgrade_profile", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upgrade_profile_get(self):
        _, artifact, _ = self._force_profile()
        self._login("mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:upgrade_profile", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade profile POST

    def test_upgrade_profile_post_different_channel(self):
        _, artifact, _ = self._force_profile()
        mobileconfig = self._build_mobileconfig(channel=Channel.DEVICE)  # different channel
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_profile", args=(artifact.pk,)),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response, "object_form", "source_file",
                             "The channel of the profile must match the channel of the artifact.")

    def test_upgrade_profile_post_same_payload(self):
        _, artifact, _ = self._force_profile()
        mobileconfig = self._build_mobileconfig()  # same payload
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_profile", args=(artifact.pk,)),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response, "object_form", "source_file",
                             "This profile is not different from the latest one.")

    def test_upgrade_profile_post_platform_not_available(self):
        _, artifact, _ = self._force_profile()
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(payload_uuid=payload_uuid)
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_profile", args=(artifact.pk,)),
                                    {"source_file": mobileconfig,
                                     "default_shard": 100,
                                     "shard_modulo": 100,
                                     "ios": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response, "version_form", "ios", "Platform not available for this artifact")

    def test_upgrade_profile_post_user_profile(self):
        blueprint, artifact, profile = self._force_profile()
        artifact_pk = str(artifact.pk)
        first_profile_pk = str(profile.artifact_version.pk)
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            list(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            [first_profile_pk]
        )
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(payload_uuid=payload_uuid)
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_profile", args=(artifact_pk,)),
                                    {"source_file": mobileconfig,
                                     "default_shard": 9,
                                     "shard_modulo": 99,
                                     "macos": "on",
                                     "macos_min_version": "13.3.1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        artifact_version = response.context["object"]
        self.assertEqual(artifact, artifact_version.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(artifact_version.version, 2)
        self.assertEqual(artifact_version.default_shard, 9)
        self.assertEqual(artifact_version.shard_modulo, 99)
        self.assertTrue(artifact_version.macos)
        self.assertEqual(artifact_version.macos_min_version, "13.3.1")
        profile = artifact_version.profile
        self.assertEqual(profile.payload_uuid, payload_uuid)
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            {first_profile_pk, str(artifact_version.pk)}
        )

    def test_upgrade_profile_post_device_profile(self):
        blueprint, artifact, profile = self._force_profile(channel=Channel.DEVICE)
        artifact_pk = str(artifact.pk)
        first_profile_pk = str(profile.artifact_version.pk)
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            list(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            [first_profile_pk]
        )
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(channel=Channel.DEVICE, payload_uuid=payload_uuid)
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        response = self.client.post(reverse("mdm:upgrade_profile", args=(artifact_pk,)),
                                    {"source_file": mobileconfig,
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
        self.assertEqual(artifact, artifact_version.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(artifact_version.version, 2)
        self.assertTrue(artifact_version.macos)
        self.assertEqual(artifact_version.macos_min_version, "14")
        self.assertEqual(list(artifact_version.excluded_tags.all()), [excluded_tag])
        self.assertEqual(artifact_version.item_tags.count(), 1)
        av_tag = artifact_version.item_tags.first()
        self.assertEqual(av_tag.tag, shard_tag)
        self.assertEqual(av_tag.shard, 99)
        profile = artifact_version.profile
        self.assertEqual(profile.payload_uuid, payload_uuid)
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            {first_profile_pk, str(profile.artifact_version.pk)}
        )

    # download profile

    def test_download_profile_login_redirect(self):
        _, _, profile = self._force_profile(channel=Channel.DEVICE)
        self._login_redirect(reverse("mdm:download_profile", args=(profile.artifact_version.pk,)))

    def test_download_profile_permission_denied(self):
        _, _, profile = self._force_profile(channel=Channel.DEVICE)
        self._login()
        response = self.client.get(reverse("mdm:download_profile", args=(profile.artifact_version.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_download_profile(self):
        _, _, profile = self._force_profile(channel=Channel.DEVICE)
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:download_profile", args=(profile.artifact_version.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Disposition"],
            f'attachment; filename="{profile.filename}"'
        )
        self.assertEqual(b"".join(response.streaming_content), profile.source)

    def test_download_profile_no_filename(self):
        _, _, profile = self._force_profile(channel=Channel.DEVICE)
        profile.filename = ""
        profile.save()
        self._login("mdm.view_artifact")
        response = self.client.get(reverse("mdm:download_profile", args=(profile.artifact_version.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response["Content-Disposition"],
            f'attachment; filename="profile_{profile.artifact_version.pk}.mobileconfig"'
        )
        self.assertEqual(b"".join(response.streaming_content), profile.source)
