from functools import reduce
from io import BytesIO
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import Artifact, Channel, DataAsset, Platform
from .utils import build_plistfile, build_zipfile, force_artifact, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MDMDataAssetManagementViewsTestCase(TestCase):
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

    # model

    def test_model_serialize_for_event(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        data_asset = artifact_version.data_asset
        self.assertEqual(
            data_asset.serialize_for_event(),
            {'artifact': {'name': artifact.name,
                          'pk': str(artifact.pk)},
             'created_at': artifact_version.created_at,
             'default_shard': 100,
             'excluded_tags': [],
             'file_sha256': data_asset.file_sha256,
             'file_size': data_asset.file_size,
             'filename': data_asset.filename,
             'ios': False,
             'ios_max_version': '',
             'ios_min_version': '',
             'ipados': False,
             'ipados_max_version': '',
             'ipados_min_version': '',
             'macos': True,
             'macos_max_version': '',
             'macos_min_version': '',
             'pk': str(artifact_version.pk),
             'shard_modulo': 100,
             'tag_shards': [],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'type': DataAsset.Type.ZIP,
             'updated_at': artifact_version.updated_at,
             'version': 1}
        )

    def test_model_get_export_filename(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        slug = artifact.name.lower()
        data_asset = artifact_version.data_asset
        self.assertEqual(
            data_asset.get_export_filename(),
            f"{slug}_{data_asset.pk}_v{artifact_version.version}.zip"
        )

    # upload data asset GET

    def test_upload_data_asset_get_redirect(self):
        self._login_redirect(reverse("mdm:upload_data_asset"))

    def test_upload_data_asset_get_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:upload_data_asset"))
        self.assertEqual(response.status_code, 403)

    def test_upload_data_asset_get(self):
        self._login("mdm.add_artifact")
        response = self.client.get(reverse("mdm:upload_data_asset"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/dataasset_form.html")

    # upload data_asset POST

    def test_upload_data_asset_post_redirect(self):
        zipfile = build_zipfile()
        self._login_redirect(reverse("mdm:upload_data_asset"),
                             {"type": str(DataAsset.Type.ZIP),
                              "file": zipfile,
                              "name": get_random_string(12),
                              "platforms": [str(Platform.MACOS)]})

    def test_upload_data_asset_post_permission_denied(self):
        zipfile = build_zipfile()
        self._login()
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.ZIP),
                                     "file": zipfile,
                                     "name": get_random_string(12),
                                     "platforms": [str(Platform.MACOS)]})
        self.assertEqual(response.status_code, 403)

    # PLIST

    def test_upload_data_asset_post_invalid_plist_ext(self):
        notaplist = BytesIO(b"-")
        notaplist.name = "test.yolo"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.PLIST),
                                     "file": notaplist,
                                     "name": get_random_string(12),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/dataasset_form.html")
        self.assertFormError(response.context["form"], "file", "File name must have a .plist extension")

    def test_upload_data_asset_post_invalid_plist(self):
        notaplist = BytesIO(b"-")
        notaplist.name = "test.plist"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.PLIST),
                                     "file": notaplist,
                                     "name": get_random_string(12),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/dataasset_form.html")
        self.assertFormError(response.context["form"], "file", "Invalid PLIST file")

    def test_upload_data_asset_post_plist(self):
        plistfile = build_plistfile()
        name = get_random_string(12)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.PLIST),
                                     "file": plistfile,
                                     "name": name,
                                     "platforms": [str(Platform.MACOS), str(Platform.IOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.DATA_ASSET)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(set(artifact.platforms), {Platform.IOS, Platform.MACOS})
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        data_asset = artifact_version.data_asset
        self.assertEqual(data_asset.type, DataAsset.Type.PLIST)
        self.assertEqual(data_asset.filename, plistfile.name)
        self.assertEqual(data_asset.get_content_type(), "text/xml")

    # ZIP

    def test_upload_data_asset_post_invalid_zip_ext(self):
        notazip = BytesIO(b"-")
        notazip.name = "test.yolo"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.ZIP),
                                     "file": notazip,
                                     "name": get_random_string(12),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/dataasset_form.html")
        self.assertFormError(response.context["form"], "file", "File name must have a .zip extension")

    def test_upload_data_asset_post_invalid_zip(self):
        notazip = BytesIO(b"-")
        notazip.name = "test.zip"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.ZIP),
                                     "file": notazip,
                                     "name": get_random_string(12),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/dataasset_form.html")
        self.assertFormError(response.context["form"], "file", "Invalid ZIP file")

    def test_upload_data_asset_post_zip(self):
        zipfile = build_zipfile()
        name = get_random_string(12)
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_data_asset"),
                                    {"type": str(DataAsset.Type.ZIP),
                                     "file": zipfile,
                                     "name": name,
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.DATA_ASSET)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(set(artifact.platforms), {Platform.MACOS})
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        data_asset = artifact_version.data_asset
        self.assertEqual(data_asset.type, DataAsset.Type.ZIP)
        self.assertEqual(data_asset.filename, zipfile.name)
        self.assertEqual(data_asset.get_content_type(), "application/zip")

    # upgrade data asset GET

    def test_upgrade_data_asset_get_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self._login_redirect(reverse("mdm:upgrade_data_asset", args=(artifact.pk,)))

    def test_upgrade_data_asset_get_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self._login("mdm.change_artifactversion")  # upgrade is creation of a new version
        response = self.client.get(reverse("mdm:upgrade_data_asset", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upgrade_data_asset_get(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self._login("mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:upgrade_data_asset", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade data asset POST

    def test_upgrade_data_asset_post_same_file_error(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        same_zipfile = BytesIO(artifact_version.data_asset.file.open("rb").read())
        same_zipfile.name = get_random_string(12) + ".zip"
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_data_asset", args=(artifact.pk,)),
                                    {"type": str(DataAsset.Type.PLIST),
                                     "file": same_zipfile,
                                     "default_shard": 9,
                                     "shard_modulo": 99,
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["form"], "file", "This file is not different from the latest one.")

    def test_upgrade_data_asset_post(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        bpa, parent_artifact, _ = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.services.configuration-files",
            decl_payload={
                "ServiceType": "com.apple.sudo",
                "DataAssetReference": f"ztl:{artifact.pk}",
            },
        )
        blueprint = bpa.blueprint
        update_blueprint_serialized_artifacts(blueprint)
        self.assertEqual(set(blueprint.serialized_artifacts.keys()), {str(artifact.pk), str(parent_artifact.pk)})
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[str(artifact.pk)]["versions"]),
            {str(artifact_version.pk)}
        )
        new_zipfile = build_zipfile(random=True)
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_data_asset", args=(artifact.pk,)),
                                    {"type": str(DataAsset.Type.ZIP),
                                     "file": new_zipfile,
                                     "default_shard": 9,
                                     "shard_modulo": 99,
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        new_artifact_version = response.context["object"]
        self.assertEqual(artifact, new_artifact_version.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(new_artifact_version.version, 2)
        self.assertEqual(new_artifact_version.default_shard, 9)
        self.assertEqual(new_artifact_version.shard_modulo, 99)
        self.assertTrue(new_artifact_version.macos)
        data_asset = new_artifact_version.data_asset
        self.assertEqual(data_asset.filename, new_zipfile.name)
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(set(blueprint.serialized_artifacts.keys()), {str(artifact.pk), str(parent_artifact.pk)})
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[str(artifact.pk)]["versions"]),
            {str(new_artifact_version.pk), str(artifact_version.pk)}
        )
