from functools import lru_cache, reduce
from io import BytesIO
import operator
import plistlib
from django.contrib.auth.models import Group, Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from utils.packages import build_dummy_package
from zentral.contrib.mdm.app_manifest import build_enterprise_app_manifest
from zentral.contrib.mdm.models import Artifact, Channel
from .utils import force_artifact, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class EnterpriseAppManagementViewsTestCase(TestCase):
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

    @lru_cache
    def _build_package(self, name="test123", version="1.0", product_archive=True):
        kwargs = {"name": name, "version": version}
        if product_archive:
            kwargs["product_archive_title"] = name
        package = BytesIO(build_dummy_package(**kwargs))
        package.name = f"{name}.pkg"
        return package

    # upload enterprise app GET

    def test_upload_enterprise_app_get_redirect(self):
        self._login_redirect(reverse("mdm:upload_enterprise_app"))

    def test_upload_enterprise_app_get_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:upload_enterprise_app"))
        self.assertEqual(response.status_code, 403)

    def test_upload_enterprise_app_get(self):
        self._login("mdm.add_artifact")
        response = self.client.get(reverse("mdm:upload_enterprise_app"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enterpriseapp_form.html")

    # upload profile POST

    def test_upload_enterprise_app_post_redirect(self):
        package = self._build_package()
        self._login_redirect(reverse("mdm:upload_enterprise_app"),
                             {"package": package})

    def test_upload_enterprise_app_post_permission_denied(self):
        package = self._build_package()
        self._login()
        response = self.client.post(reverse("mdm:upload_enterprise_app"),
                                    {"package": package})
        self.assertEqual(response.status_code, 403)

    def test_upload_enterprise_app_post_could_not_read_distribution_file(self):
        notapackage = BytesIO(b"-")
        notapackage.name = "test.pkg"
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_enterprise_app"),
                                    {"package": notapackage},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/enterpriseapp_form.html")
        self.assertFormError(response.context["form"], None, "Invalid app: Could not read Distribution file")

    def test_upload_enterprise_app_post(self):
        package = self._build_package()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_enterprise_app"),
                                    {"package": package},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "Artifact created")
        self.assertContains(response, "io.zentral.test123")
        artifact = response.context["object"]
        self.assertEqual(artifact.type, Artifact.Type.ENTERPRISE_APP)
        self.assertEqual(artifact.channel, Channel.DEVICE)
        self.assertEqual(artifact.name, "io.zentral.test123")
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        self.assertEqual(artifact_version.version, 1)
        enterprise_app = artifact_version.enterprise_app
        self.assertEqual(enterprise_app.product_id, "io.zentral.test123")
        self.assertEqual(enterprise_app.product_version, "1.0")
        self.assertIsNone(enterprise_app.get_configuration())
        self.assertFalse(enterprise_app.ios_app)
        self.assertFalse(enterprise_app.remove_on_unenroll)

    def test_upload_enterprise_app_post_existing_enteprise_app(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        artifact.name = "io.zentral.test123"  # prepare name collision
        artifact.save()
        package = self._build_package()
        self._login("mdm.add_artifact", "mdm.view_artifact")
        response = self.client.post(reverse("mdm:upload_enterprise_app"),
                                    {"package": package},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        self.assertContains(response, "io.zentral.test123 (1)")
        artifact = response.context["object"]
        self.assertEqual(artifact.name, "io.zentral.test123 (1)")

    # upgrade enterprise app GET

    def test_upgrade_enterprise_app_get_login_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self._login_redirect(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)))

    def test_upgrade_enterprise_app_get_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self._login()
        response = self.client.get(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upgrade_enterprise_app_get(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        self._login("mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade profile POST

    def test_upgrade_enterprise_app_post_same_package(self):
        artifact, (enterprise_app_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        package = self._build_package()
        uploaded_package = SimpleUploadedFile(package.name, package.read())
        _, product_id, product_version, manifest, bundles, _ = build_enterprise_app_manifest(uploaded_package)
        enterprise_app = enterprise_app_av.enterprise_app
        enterprise_app.package = uploaded_package
        enterprise_app.product_id = product_id
        enterprise_app.product_version = product_version
        enterprise_app.manifest = manifest
        enterprise_app.bundles = bundles
        enterprise_app.configuration = plistlib.dumps({"un": 1})
        enterprise_app.save()
        package.seek(0)
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)),
                                    {"package": package,
                                     "configuration": plistlib.dumps({"un": 1}).decode("utf-8")},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["object_form"], None,
                             "This version of the enterprise app is identical to the latest version")

    def test_upgrade_enterprise_app_post_platform_not_available(self):
        artifact, (enterprise_app_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        package = self._build_package()
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)),
                                    {"package": package,
                                     "default_shard": 100,
                                     "shard_modulo": 100,
                                     "ios": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["version_form"], "ios", "Platform not available for this artifact")

    def test_upgrade_enterprise_app_post_different_product_id(self):
        artifact, (enterprise_app_av,) = force_artifact(artifact_type=Artifact.Type.ENTERPRISE_APP)
        enterprise_app_av.enterprise_app.product_id = "yolo"  # not the same
        enterprise_app_av.enterprise_app.save()
        package = self._build_package()
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_enterprise_app", args=(artifact.pk,)),
                                    {"package": package,
                                     "default_shard": 100,
                                     "shard_modulo": 100,
                                     "macos": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["object_form"], "package",
                             "The product ID of the new app is not identical to the product ID of the latest version")

    def test_upgrade_enterprise_app_post(self):
        blueprint_artifact, artifact, (enterprise_app_av1,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        enterprise_app_av1.enterprise_app.product_id = "io.zentral.test123"
        enterprise_app_av1.enterprise_app.save()
        blueprint = blueprint_artifact.blueprint
        artifact_pk = str(artifact.pk)
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            list(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            [str(enterprise_app_av1.pk)]
        )
        package = self._build_package()
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_enterprise_app", args=(artifact_pk,)),
                                    {"package": package,
                                     "configuration": plistlib.dumps({"deux": 2}).decode("utf-8"),
                                     "default_shard": 9,
                                     "shard_modulo": 99,
                                     "macos": "on",
                                     "macos_min_version": "13.3.1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        enterprise_app_av2 = response.context["object"]
        self.assertEqual(artifact, enterprise_app_av2.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(enterprise_app_av2.version, 2)
        self.assertEqual(enterprise_app_av2.default_shard, 9)
        self.assertEqual(enterprise_app_av2.shard_modulo, 99)
        self.assertTrue(enterprise_app_av2.macos)
        self.assertEqual(enterprise_app_av2.macos_min_version, "13.3.1")
        enterprise_app = enterprise_app_av2.enterprise_app
        self.assertEqual(enterprise_app.get_configuration(), {"deux": 2})
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            {str(enterprise_app_av1.pk), str(enterprise_app_av2.pk)}
        )
