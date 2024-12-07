from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.models import Artifact, Channel, Platform
from .utils import force_artifact, force_blueprint_artifact


@override_settings(
    STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage',
    STORAGES={"default": {"BACKEND": "django.core.files.storage.InMemoryStorage"}}
)
class MDMDeclarationManagementViewsTestCase(TestCase):
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
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        declaration = artifact_version.declaration
        self.assertEqual(
            declaration.serialize_for_event(),
            {'artifact': {'name': artifact.name,
                          'pk': str(artifact.pk)},
             'created_at': artifact_version.created_at,
             'default_shard': 100,
             'excluded_tags': [],
             'identifier': declaration.identifier,
             'ios': False,
             'ios_max_version': '',
             'ios_min_version': '',
             'ipados': False,
             'ipados_max_version': '',
             'ipados_min_version': '',
             'macos': True,
             'macos_max_version': '',
             'macos_min_version': '',
             'payload': declaration.payload,
             'pk': str(artifact_version.pk),
             'server_token': declaration.server_token,
             'shard_modulo': 100,
             'tag_shards': [],
             'tvos': False,
             'tvos_max_version': '',
             'tvos_min_version': '',
             'type': declaration.type,
             'updated_at': artifact_version.updated_at,
             'version': 1}
        )

    def test_model_get_export_filename(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.ASSET)
        slug = artifact.name.lower()
        declaration = artifact_version.declaration
        self.assertEqual(
            declaration.get_export_filename(),
            f"{slug}_{declaration.pk}_v{artifact_version.version}.json"
        )

    # create declaration GET

    def test_create_declaration_get_redirect(self):
        for suffix in ("activation", "asset", "configuration", "manual_configuration"):
            self._login_redirect(reverse(f"mdm:create_{suffix}"))

    def test_create_declaration_get_permission_denied(self):
        self._login()
        for suffix in ("activation", "asset", "configuration", "manual_configuration"):
            response = self.client.get(reverse(f"mdm:create_{suffix}"))
            self.assertEqual(response.status_code, 403)

    def test_create_declaration_get(self):
        self._login("mdm.add_artifact")
        for suffix in ("activation", "asset", "configuration", "manual_configuration"):
            response = self.client.get(reverse(f"mdm:create_{suffix}"))
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "mdm/declaration_form.html")

    # create declaration POST

    def test_create_declaration_post_redirect(self):
        for suffix in ("activation", "asset", "configuration", "manual_configuration"):
            self._login_redirect(reverse(f"mdm:create_{suffix}"), {"yolo": "fomo"})

    def test_create_declaration_post_permission_denied(self):
        self._login()
        for suffix in ("activation", "asset", "configuration", "manual_configuration"):
            response = self.client.post(reverse(f"mdm:create_{suffix}"), {"yolo": "fomo"})
            self.assertEqual(response.status_code, 403)

    def test_create_declaration_post_invalid_declaration_type(self):
        self._login("mdm.add_artifact")
        for artifact_type in (t for t in Artifact.Type if t.is_raw_declaration):
            suffix = artifact_type.label.lower().replace(" ", "_")
            response = self.client.post(reverse(f"mdm:create_{suffix}"),
                                        {"source": json.dumps({
                                            "Identifier": "yolo",
                                            "Type": "com.apple.management.server-capabilities",
                                            "Payload": {},
                                         }),
                                         "name": get_random_string(12),
                                         "channel": str(Channel.DEVICE),
                                         "platforms": [str(Platform.MACOS)]},
                                        follow=True)
            self.assertEqual(response.status_code, 200)
            self.assertTemplateUsed(response, "mdm/declaration_form.html")
            self.assertFormError(response.context["form"], "source", f"Invalid declaration Type for {artifact_type}")

    def test_create_declaration_post_name_conflict(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login("mdm.add_artifact")
        response = self.client.post(reverse("mdm:create_asset"),
                                    {"source": json.dumps({
                                        "Identifier": "yolo",
                                        "Type": "com.apple.asset.data",
                                        "Payload": {},
                                     }),
                                     "name": artifact.name,
                                     "channel": str(Channel.DEVICE),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/declaration_form.html")
        self.assertFormError(response.context["form"], "name", "An artifact with this name already exists")

    def test_create_declaration_post_identifier_conflict(self):
        _, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login("mdm.add_artifact")
        response = self.client.post(reverse("mdm:create_asset"),
                                    {"source": json.dumps({
                                        "Identifier": av.declaration.identifier,
                                        "Type": "com.apple.asset.data",
                                        "Payload": {},
                                     }),
                                     "name": get_random_string(12),
                                     "channel": str(Channel.DEVICE),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/declaration_form.html")
        self.assertFormError(response.context["form"], "source", "A declaration with this Identifier already exists")

    def test_create_declaration_post_server_token_conflict(self):
        _, (av,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login("mdm.add_artifact")
        response = self.client.post(reverse("mdm:create_asset"),
                                    {"source": json.dumps({
                                        "Identifier": "yolo",
                                        "ServerToken": av.declaration.server_token,
                                        "Type": "com.apple.asset.data",
                                        "Payload": {},
                                     }),
                                     "name": get_random_string(12),
                                     "channel": str(Channel.DEVICE),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/declaration_form.html")
        self.assertFormError(response.context["form"], "source", "A declaration with this ServerToken already exists")

    def test_create_declaration_post_different_channel(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        self._login("mdm.add_artifact")
        identifier = get_random_string(12)
        response = self.client.post(reverse("mdm:create_configuration"),
                                    {"source": json.dumps({
                                        "Identifier": identifier,
                                        "Type": "com.apple.configuration.services.configuration-files",
                                        "Payload": {
                                            "ServiceType": "com.apple.sudo",
                                            "DataAssetReference": f"ztl:{artifact.pk}"
                                        },
                                     }),
                                     "name": get_random_string(12),
                                     "channel": str(Channel.USER),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "source",
                             f"Referenced artifact ztl:{artifact.pk} on a different channel.")

    def test_create_declaration_post_different_platforms(self):
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.DATA_ASSET,
            platforms=[Platform.IOS],
        )
        self._login("mdm.add_artifact")
        identifier = get_random_string(12)
        response = self.client.post(reverse("mdm:create_configuration"),
                                    {"source": json.dumps({
                                        "Identifier": identifier,
                                        "Type": "com.apple.configuration.services.configuration-files",
                                        "Payload": {
                                            "ServiceType": "com.apple.sudo",
                                            "DataAssetReference": f"ztl:{artifact.pk}"
                                        },
                                     }),
                                     "name": get_random_string(12),
                                     "channel": str(Channel.DEVICE),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "source",
                             f"Referenced artifact ztl:{artifact.pk} not available for all platforms.")

    def test_create_declaration_post(self):
        data_asset_artifact, (data_asset_artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.DATA_ASSET,
        )
        self._login("mdm.add_artifact", "mdm.view_artifact")
        name = get_random_string(12)
        identifier = get_random_string(12)
        response = self.client.post(reverse("mdm:create_configuration"),
                                    {"source": json.dumps({
                                        "Identifier": identifier,
                                        "Type": "com.apple.configuration.services.configuration-files",
                                        "Payload": {
                                            "ServiceType": "com.apple.sudo",
                                            "DataAssetReference": f"ztl:{data_asset_artifact.pk}"
                                        },
                                     }),
                                     "name": name,
                                     "channel": str(Channel.DEVICE),
                                     "platforms": [str(Platform.MACOS)]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.CONFIGURATION)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(set(artifact.platforms), {Platform.MACOS})
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        declaration = artifact_version.declaration
        self.assertEqual(
            declaration.get_full_dict(),
            {'Type': 'com.apple.configuration.services.configuration-files',
             'Identifier': identifier,
             'ServerToken': declaration.server_token,
             'Payload': {
                 'ServiceType': 'com.apple.sudo',
                 'DataAssetReference': f'ztl:{data_asset_artifact.pk}'
             }}
        )
        ref_qs = declaration.declarationref_set.all()
        self.assertEqual(ref_qs.count(), 1)
        ref = ref_qs.first()
        self.assertEqual(ref.artifact, data_asset_artifact)
        self.assertEqual(ref.key, ["DataAssetReference"])

    # upgrade declaration POST

    def test_upgrade_declaration_get_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login_redirect(reverse("mdm:upgrade_declaration", args=(artifact.pk,)))

    def test_upgrade_declaration_get_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login()
        response = self.client.get(reverse("mdm:upgrade_declaration", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upgrade_declaration_post_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login_redirect(reverse("mdm:upgrade_declaration", args=(artifact.pk,)), {"un": 2})

    def test_upgrade_declaration_post_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        self._login("mdm.change_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)), {"un": 2})
        self.assertEqual(response.status_code, 403)

    def test_upgrade_declaration_post_different_type_error(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        declaration = artifact_version.declaration
        self._login("mdm.add_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)),
                                    {"source": json.dumps({
                                     "Identifier": declaration.identifier,
                                     "Type": "com.apple.configuration.management.test",
                                     "Payload": {"un": 2},
                                     }),
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["form"], "source",
                             "The new declaration Type is different from the existing one")

    def test_upgrade_declaration_post_different_identifier_error(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        declaration = artifact_version.declaration
        self._login("mdm.add_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)),
                                    {"source": json.dumps({
                                     "Identifier": "yolo",
                                     "Type": declaration.type,
                                     "Payload": {"un": 2},
                                     }),
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["form"], "source",
                             "The new declaration Identifier is different from the existing one")

    def test_upgrade_declaration_post_same_payload_error(self):
        artifact, (artifact_version,) = force_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        declaration = artifact_version.declaration
        self._login("mdm.add_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)),
                                    {"source": json.dumps({
                                     "Identifier": declaration.identifier,
                                     "Type": declaration.type,
                                     "Payload": declaration.payload,
                                     }),
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["form"], "source",
                             "The new declaration Payload is the same as the latest one")

    def test_upgrade_declaration_post(self):
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(artifact_type=Artifact.Type.CONFIGURATION)
        blueprint = bpa.blueprint
        declaration = artifact_version.declaration
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_declaration", args=(artifact.pk,)),
                                    {"source": json.dumps({
                                     "Identifier": declaration.identifier,
                                     "Type": declaration.type,
                                     "Payload": {
                                         'Restrictions': {
                                             'ExternalStorage': 'Disallowed',
                                             'NetworkStorage': 'Allowed'
                                         }
                                     }}),
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
        declaration = new_artifact_version.declaration
        self.assertEqual(
            declaration.get_full_dict(),
            {'Type': 'com.apple.configuration.diskmanagement.settings',
             'Identifier': declaration.identifier,
             'ServerToken': declaration.server_token,
             'Payload': {
                 'Restrictions': {
                     'ExternalStorage': 'Disallowed',
                     'NetworkStorage': 'Allowed',
                 },
              }
             }
        )
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(set(blueprint.serialized_artifacts.keys()), {str(artifact.pk)})
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[str(artifact.pk)]["versions"]),
            {str(new_artifact_version.pk), str(artifact_version.pk)}
        )
