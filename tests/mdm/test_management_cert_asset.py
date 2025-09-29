from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import Artifact, Channel, Platform
from .utils import (
    force_acme_issuer,
    force_artifact,
    force_blueprint_artifact,
    force_scep_issuer,
)


@override_settings(
    STATICFILES_STORAGE="django.contrib.staticfiles.storage.StaticFilesStorage"
)
class MDMCertAssetManagementViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            "godzilla", "godzilla@zentral.io", get_random_string(12)
        )
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
            permission_filter = reduce(
                operator.or_,
                (
                    Q(content_type__app_label=app_label, codename=codename)
                    for app_label, codename in (
                        permission.split(".") for permission in permissions
                    )
                ),
            )
            self.group.permissions.set(
                list(Permission.objects.filter(permission_filter))
            )
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    # model

    def test_model_serialize_for_event(self):
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        cert_asset = artifact_version.cert_asset
        self.assertEqual(
            cert_asset.serialize_for_event(),
            {
                "accessible": "Default",
                "acme_issuer": {
                    "name": cert_asset.acme_issuer.name,
                    "pk": str(cert_asset.acme_issuer.pk),
                },
                "artifact": {"name": artifact.name, "pk": str(artifact.pk)},
                "created_at": artifact_version.created_at,
                "default_shard": 100,
                "excluded_tags": [],
                "ios": False,
                "ios_max_version": "",
                "ios_min_version": "",
                "ipados": False,
                "ipados_max_version": "",
                "ipados_min_version": "",
                "macos": True,
                "macos_max_version": "",
                "macos_min_version": "",
                "pk": str(artifact_version.pk),
                "scep_issuer": {
                    "name": cert_asset.scep_issuer.name,
                    "pk": str(cert_asset.scep_issuer.pk),
                },
                "shard_modulo": 100,
                "subject": [{"type": "CN", "value": "YOLO"}],
                "subject_alt_name": {
                    "dNSName": "yolo.example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "rfc822Name": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "tag_shards": [],
                "tvos": False,
                "tvos_max_version": "",
                "tvos_min_version": "",
                "updated_at": artifact_version.updated_at,
                "version": 1,
            },
        )

    def test_model_get_subject_alt_name_display(self):
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        cert_asset = artifact_version.cert_asset
        cert_asset.subject_alt_name["dNSName"] = None
        self.assertEqual(
            cert_asset.get_subject_alt_name_display(),
            {
                "rfc822Name": "yolo@example.com",
                "ntPrincipalName": "yolo@example.com",
                "uniformResourceIdentifier": "https://example.com/yolo",
            },
        )

    # create cert asset GET

    def test_create_cert_asset_get_redirect(self):
        self._login_redirect(reverse("mdm:create_cert_asset"))

    def test_create_cert_asset_get_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_cert_asset"))
        self.assertEqual(response.status_code, 403)

    def test_create_cert_asset_get(self):
        self._login("mdm.add_artifact")
        response = self.client.get(reverse("mdm:create_cert_asset"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/certasset_form.html")

    # create cert_asset POST

    def test_create_cert_asset_post_redirect(self):
        acme_issuer = force_acme_issuer()
        self._login_redirect(
            reverse("mdm:create_cert_asset"),
            {
                "name": get_random_string(12),
                "channel": "DEVICE",
                "platforms": [str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([{"type": "CN", "value": "yolo"}]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
        )

    def test_create_cert_asset_post_permission_denied(self):
        acme_issuer = force_acme_issuer()
        self._login()
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": get_random_string(12),
                "channel": "DEVICE",
                "platforms": [str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([{"type": "CN", "value": "yolo"}]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
        )
        self.assertEqual(response.status_code, 403)

    def test_create_cert_asset_post_name_error(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        acme_issuer = force_acme_issuer()
        self._login("mdm.add_artifact")
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": artifact.name,
                "channel": "DEVICE",
                "platforms": [str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([{"type": "CN", "value": "yolo"}]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/certasset_form.html")
        self.assertFormError(
            response.context["form"],
            "name",
            "An artifact with this name already exists",
        )

    def test_create_cert_asset_post_missing_fields(self):
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:create_cert_asset"), {})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/certasset_form.html")
        self.assertFormError(
            response.context["form"], None, "An ACME issuer or SCEP issuer is required."
        )
        self.assertFormError(response.context["form"], "subject", "Invalid Subject.")
        self.assertFormError(
            response.context["form"], "subject_alt_name", "Invalid SubjectAltName."
        )
        self.assertFormError(
            response.context["form"], "accessible", "This field is required."
        )
        self.assertFormError(
            response.context["form"], "name", "This field is required."
        )
        self.assertFormError(
            response.context["form"], "channel", "This field is required."
        )
        self.assertFormError(
            response.context["form"], "platforms", "This field is required."
        )

    def test_create_cert_asset_post_subject_or_san_required(self):
        acme_issuer = force_acme_issuer()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": get_random_string(12),
                "channel": Channel.DEVICE,
                "platforms": [str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/certasset_form.html")
        self.assertFormError(
            response.context["form"], None, "A Subject or SubjectAltName is required."
        )

    def test_create_cert_asset_post_invalid_rdn(self):
        acme_issuer = force_acme_issuer()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": get_random_string(12),
                "channel": Channel.DEVICE,
                "platforms": [str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([{"type": "yolo", "value": "fomo"}]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/certasset_form.html")
        self.assertFormError(response.context["form"], "subject", "Invalid Subject.")

    def test_create_cert_asset_post(self):
        acme_issuer = force_acme_issuer()
        name = get_random_string(12)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": name,
                "channel": Channel.DEVICE,
                "platforms": [str(Platform.IOS), str(Platform.MACOS)],
                "acme_issuer": acme_issuer.pk,
                "subject": json.dumps([{"type": "CN", "value": "fomo"}]),
                "subject_alt_name": json.dumps({}),
                "accessible": "Default",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.CERT_ASSET)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(set(artifact.platforms), {Platform.IOS, Platform.MACOS})
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        cert_asset = artifact_version.cert_asset
        self.assertEqual(cert_asset.acme_issuer, acme_issuer)
        self.assertIsNone(cert_asset.scep_issuer)
        self.assertEqual(cert_asset.subject, [{"type": "CN", "value": "fomo"}])
        self.assertEqual(
            cert_asset.subject_alt_name,
            {
                "dNSName": None,
                "uniformResourceIdentifier": None,
                "rfc822Name": None,
                "ntPrincipalName": None,
            },
        )
        self.assertEqual(cert_asset.accessible, "Default")

    def test_create_cert_asset_post_2(self):
        scep_issuer = force_scep_issuer()
        name = get_random_string(12)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(
            reverse("mdm:create_cert_asset"),
            {
                "name": name,
                "channel": Channel.DEVICE,
                "platforms": [str(Platform.IOS), str(Platform.MACOS)],
                "scep_issuer": scep_issuer.pk,
                "subject": json.dumps([{"type": "2.5.4.5", "value": "012345678910"}]),
                "subject_alt_name": json.dumps({"rfc822Name": "yolo@example.com"}),
                "accessible": "AfterFirstUnlock",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.CERT_ASSET)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(set(artifact.platforms), {Platform.IOS, Platform.MACOS})
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        cert_asset = artifact_version.cert_asset
        self.assertIsNone(cert_asset.acme_issuer)
        self.assertEqual(cert_asset.scep_issuer, scep_issuer)
        self.assertEqual(
            cert_asset.subject, [{"type": "2.5.4.5", "value": "012345678910"}]
        )
        self.assertEqual(
            cert_asset.subject_alt_name,
            {
                "dNSName": None,
                "uniformResourceIdentifier": None,
                "rfc822Name": "yolo@example.com",
                "ntPrincipalName": None,
            },
        )
        self.assertEqual(cert_asset.accessible, "AfterFirstUnlock")

    # upgrade cert asset GET

    def test_upgrade_cert_asset_get_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        self._login_redirect(reverse("mdm:upgrade_cert_asset", args=(artifact.pk,)))

    def test_upgrade_cert_asset_get_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        self._login(
            "mdm.change_artifactversion"
        )  # upgrade is creation of a new version
        response = self.client.get(
            reverse("mdm:upgrade_cert_asset", args=(artifact.pk,))
        )
        self.assertEqual(response.status_code, 403)

    def test_upgrade_cert_asset_get(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CERT_ASSET)
        self._login("mdm.add_artifactversion")
        response = self.client.get(
            reverse("mdm:upgrade_cert_asset", args=(artifact.pk,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade cert asset POST

    def test_upgrade_cert_asset_post(self):
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        bpa, parent_artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.security.identity",
            decl_payload={
                "KeyIsExtractable": False,
                "AllowAllAppsAccess": True,
                "CredentialAssetReference": f"ztl:{artifact.pk}",
            },
        )
        blueprint = bpa.blueprint
        update_blueprint_serialized_artifacts(blueprint)
        self.assertEqual(
            set(blueprint.serialized_artifacts.keys()),
            {str(artifact.pk), str(parent_artifact.pk)},
        )
        self.assertEqual(
            set(
                str(av["pk"])
                for av in blueprint.serialized_artifacts[str(artifact.pk)]["versions"]
            ),
            {str(artifact_version.pk)},
        )
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        cert_asset = artifact_version.cert_asset
        acme_issuer = cert_asset.acme_issuer
        scep_issuer = cert_asset.scep_issuer
        response = self.client.post(
            reverse("mdm:upgrade_cert_asset", args=(artifact.pk,)),
            {
                "acme_issuer": acme_issuer.pk,
                "scep_issuer": scep_issuer.pk,
                "subject": json.dumps([{"type": "2.5.4.5", "value": "012345678910"}]),
                "subject_alt_name": json.dumps({"rfc822Name": "voila@example.com"}),
                "accessible": "AfterFirstUnlock",
                "default_shard": 9,
                "shard_modulo": 99,
                "macos": "on",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        new_artifact_version = response.context["object"]
        self.assertEqual(artifact, new_artifact_version.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(new_artifact_version.version, 2)
        self.assertEqual(new_artifact_version.default_shard, 9)
        self.assertEqual(new_artifact_version.shard_modulo, 99)
        self.assertTrue(new_artifact_version.macos)
        cert_asset = new_artifact_version.cert_asset
        self.assertEqual(cert_asset.acme_issuer, acme_issuer)
        self.assertEqual(cert_asset.scep_issuer, scep_issuer)
        self.assertEqual(
            cert_asset.subject, [{"type": "2.5.4.5", "value": "012345678910"}]
        )
        self.assertEqual(
            cert_asset.subject_alt_name,
            {
                "rfc822Name": "voila@example.com",
                "dNSName": None,
                "uniformResourceIdentifier": None,
                "ntPrincipalName": None,
            },
        )
        self.assertEqual(cert_asset.accessible, "AfterFirstUnlock")
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(
            set(blueprint.serialized_artifacts.keys()),
            {str(artifact.pk), str(parent_artifact.pk)},
        )
        self.assertEqual(
            set(
                str(av["pk"])
                for av in blueprint.serialized_artifacts[str(artifact.pk)]["versions"]
            ),
            {str(new_artifact_version.pk), str(artifact_version.pk)},
        )
