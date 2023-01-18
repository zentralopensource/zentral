import copy
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
from zentral.contrib.mdm.declarations import update_blueprint_activation, update_blueprint_declaration_items
from zentral.contrib.mdm.models import (Artifact, ArtifactType, ArtifactVersion,
                                        Blueprint, BlueprintArtifact, Channel, Platform, Profile)


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
        if channel == Channel.Device:
            payload["PayloadScope"] = "System"
        elif channel == Channel.User:
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
        payload_scope=None
    ):
        payload = self._get_payload(
            channel=channel,
            payload_uuid=payload_uuid,
            missing_payload_id=missing_payload_id,
            missing_payload_uuid=missing_payload_uuid,
            payload_scope=payload_scope,
        )
        mobileconfig = BytesIO(plistlib.dumps(payload))
        mobileconfig.name = "test.mobileconfig"
        return mobileconfig

    def _force_profile(self, channel=None, payload_id=None):
        payload = self._get_payload(channel=channel, payload_id=payload_id)
        artifact = Artifact.objects.create(
            name=payload["PayloadDisplayName"],
            type=ArtifactType.Profile.name,
            channel=channel.name if channel else Channel.User.name,
            platforms=[Platform.macOS.name],
        )
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=1
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
        BlueprintArtifact.objects.create(
            blueprint=blueprint,
            artifact=artifact,
            install_before_setup_assistant=False,
            auto_update=True,
            priority=100,
        )
        update_blueprint_activation(blueprint, commit=False)
        update_blueprint_declaration_items(blueprint)
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
        self.assertEqual(artifact.type, ArtifactType.Profile.name)
        self.assertEqual(artifact.channel, Channel.User.name)  # PayloadScope not present → User
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

    def test_upload_profile_post_existing_profile(self):
        self._force_profile()
        mobileconfig = self._build_mobileconfig()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact already exists")

    def test_upload_profile_post_update_user_profile(self):
        blueprint, _, _ = self._force_profile()
        self.assertEqual(len(blueprint.activation["Payload"]["StandardConfigurations"]), 1)  # no User profiles
        self.assertEqual(len(blueprint.declaration_items["Declarations"]["Configurations"]), 1)  # no User profiles
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(payload_uuid=payload_uuid)  # new UUID → new version
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact updated")
        artifact = response.context["object"]
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        artifact_version = artifact.artifactversion_set.order_by("-version").first()
        self.assertEqual(artifact_version.version, 2)
        profile = artifact_version.profile
        self.assertEqual(profile.payload_uuid, payload_uuid)
        blueprint.refresh_from_db()
        self.assertEqual(len(blueprint.activation["Payload"]["StandardConfigurations"]), 1)  # no User profiles
        self.assertEqual(len(blueprint.declaration_items["Declarations"]["Configurations"]), 1)  # no User profiles

    def test_upload_profile_post_update_device_profile(self):
        blueprint, _, profile = self._force_profile(channel=Channel.Device)
        server_token = str(profile.artifact_version.pk)
        blueprint_activation = copy.deepcopy(blueprint.activation)
        self.assertEqual(len(blueprint.activation["Payload"]["StandardConfigurations"]), 2)  # one device profile
        self.assertEqual(
            len([cfg for cfg in blueprint.declaration_items["Declarations"]["Configurations"]
                 if cfg["ServerToken"] == server_token]),
            1
        )  # one device profile
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(channel=Channel.Device, payload_uuid=payload_uuid)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact updated")
        artifact = response.context["object"]
        self.assertEqual(artifact.channel, Channel.Device.name)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        artifact_version = artifact.artifactversion_set.order_by("-version").first()
        self.assertEqual(artifact_version.version, 2)
        profile = artifact_version.profile
        self.assertEqual(profile.payload_uuid, payload_uuid)
        blueprint.refresh_from_db()
        self.assertEqual(blueprint.activation, blueprint_activation)  # no changes in scope
        # blueprint declaration items updated
        self.assertEqual(len(blueprint.declaration_items["Declarations"]["Configurations"]), 2)  # one device profile
        self.assertEqual(
            len([cfg for cfg in blueprint.declaration_items["Declarations"]["Configurations"]
                 if cfg["ServerToken"] == str(artifact_version.pk)]),
            1
        )
        self.assertEqual(
            len([cfg for cfg in blueprint.declaration_items["Declarations"]["Configurations"]
                 if cfg["ServerToken"] == str(server_token)]),
            0
        )

    def test_upload_profile_post_existing_profile_different_channel(self):
        self._force_profile(channel=Channel.Device)
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(payload_uuid=payload_uuid)  # new UUID → new version
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(
            response, "form", "source_file",
            "Existing profile with same payload identifier has a different channel."
        )

    def test_upload_profile_post_existing_profile_same_name_different_id(self):
        self._force_profile(payload_id="com.example.my-other-profile-yolo")
        payload_uuid = str(uuid.uuid4()).upper()
        mobileconfig = self._build_mobileconfig(payload_uuid=payload_uuid)  # new UUID → new version
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_profile"),
                                    {"source_file": mobileconfig},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/profile_form.html")
        self.assertFormError(
            response, "form", "source_file",
            "An artifact with the same name but a different payload identifier already exists."
        )
