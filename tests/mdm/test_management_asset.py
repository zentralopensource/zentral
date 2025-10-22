import datetime
from functools import reduce
import operator
import plistlib
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion, Asset,
                                        Channel, Location, LocationAsset, Platform, StoreApp)
from .utils import force_artifact, force_blueprint_artifact


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AssetManagementViewsTestCase(TestCase):
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

    def _force_asset(self, supported_platforms=None):
        if supported_platforms is None:
            supported_platforms = [
                "iOS",
                "macOS",
                "visionOS",  # not supported in artifact version
            ]
        return Asset.objects.create(
            adam_id=get_random_string(12, allowed_chars="0123456789"),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=supported_platforms,
            name=get_random_string(12),
            bundle_id="pro.zentral.tests"
        )

    def _force_location_asset(self, artifacts=False):
        asset = self._force_asset()
        location = Location(
            server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
            server_token=get_random_string(12),
            server_token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            name=get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        location.set_notification_auth_token()
        location.save()
        location_asset = LocationAsset.objects.create(
            asset=asset,
            location=location
        )
        if artifacts:
            for i in range(2):
                artifact = Artifact.objects.create(
                    name=get_random_string(12),
                    type=Artifact.Type.STORE_APP,
                    channel=Channel.DEVICE,
                    platforms=[Platform.MACOS]
                )
                artifact_version = ArtifactVersion.objects.create(
                    artifact=artifact,
                    version=0,
                    macos=True
                )
                StoreApp.objects.create(
                    artifact_version=artifact_version,
                    location_asset=location_asset
                )
        return location_asset

    # asset model

    def test_asset_with_name_str(self):
        asset = self._force_asset()
        self.assertEqual(str(asset), f"App {asset.name}")

    def test_asset_without_name_str(self):
        asset = self._force_asset()
        asset.name = None
        asset.save()
        self.assertEqual(str(asset), f"App {asset.adam_id} {asset.pricing_param}")

    def test_location_asset_str(self):
        location_asset = self._force_location_asset()
        self.assertEqual(str(location_asset), f"{location_asset.location.name} - App {location_asset.asset.name}")

    def test_asset_icon_no_metadata(self):
        asset = self._force_asset()
        self.assertIsNone(asset.icon_url)

    def test_asset_icon_missing_metadata(self):
        asset = self._force_asset()
        asset.metadata = {"un": 2}
        self.assertIsNone(asset.icon_url)

    def test_asset_icon(self):
        asset = self._force_asset()
        asset.metadata = {"artwork": {"width": 512, "height": 1024, "url": "https://example.com/{w}x{h}bb.{f}"}}
        self.assertEqual(asset.icon_url, "https://example.com/128x128bb.png")

    def test_asset_lastest_version(self):
        asset = self._force_asset()
        asset.metadata = {
            "offers": [
                {"un": 2},
                {"version": {"display": "INVALID"}},
                {"version": {"display": "13.1"}},
                {"version": {"display": "13.1.1"}},
                {"version": {"display": "13.0"}},
            ]
        }
        self.assertEqual(asset.lastest_version, "13.1.1")

    def test_asset_platforms(self):
        asset = self._force_asset()
        self.assertIn("iOS", asset.supported_platforms)
        self.assertNotIn("iPadOS", asset.supported_platforms)
        self.assertEqual(
            set(asset.get_artifact_platforms()),
            set([Platform.IOS, Platform.IPADOS, Platform.MACOS])
        )

    def test_asset_platforms_2(self):
        asset = self._force_asset(supported_platforms=["macOS"])
        self.assertEqual(
            asset.get_artifact_platforms(),
            [Platform.MACOS],
        )

    # assets

    def test_assets_redirect(self):
        self._login_redirect(reverse("mdm:assets"))

    def test_assets_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:assets"))
        self.assertEqual(response.status_code, 403)

    def test_assets(self):
        asset = self._force_asset()
        self._login("mdm.view_asset")
        response = self.client.get(reverse("mdm:assets"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/asset_list.html")
        self.assertContains(response, asset.name)
        self.assertContains(response, asset.bundle_id)

    # asset

    def test_asset_redirect(self):
        asset = self._force_asset()
        self._login_redirect(reverse("mdm:asset", args=(asset.pk,)))

    def test_asset_permission_denied(self):
        self._login()
        asset = self._force_asset()
        response = self.client.get(reverse("mdm:asset", args=(asset.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_asset(self):
        self._login("mdm.view_asset")
        asset = self._force_asset()
        response = self.client.get(reverse("mdm:asset", args=(asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/asset_detail.html")
        self.assertContains(response, asset.name)
        self.assertContains(response, asset.bundle_id)
        self.assertContains(response, asset.adam_id)
        self.assertContains(response, asset.pricing_param)
        self.assertContains(response, "No artifacts found for this asset.")
        self.assertNotContains(response, reverse("mdm:create_asset_artifact", args=(asset.pk,)))

    def test_asset_with_add_artifact(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        asset = self._force_asset()
        response = self.client.get(reverse("mdm:asset", args=(asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/asset_detail.html")
        self.assertContains(response, reverse("mdm:create_asset_artifact", args=(asset.pk,)))

    def test_asset_with_artifact(self):
        location_asset = self._force_location_asset(artifacts=True)
        artifact = location_asset.storeapp_set.first().artifact_version.artifact
        self._login("mdm.view_asset")
        response = self.client.get(reverse("mdm:asset", args=(location_asset.asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/asset_detail.html")
        self.assertNotContains(response, "No artifacts found for this asset.")
        self.assertContains(response, artifact.name)

    # create_asset_artifact

    def test_create_asset_artifact_login_redirect(self):
        asset = self._force_asset()
        self._login_redirect(reverse("mdm:create_asset_artifact", args=(asset.pk,)))

    def test_create_asset_artifact_permission_denied(self):
        self._login()
        asset = self._force_asset()
        response = self.client.get(reverse("mdm:create_asset_artifact", args=(asset.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_asset_artifact_get(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        asset = self._force_asset()
        response = self.client.get(reverse("mdm:create_asset_artifact", args=(asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        self.assertContains(response, asset.name)
        self.assertContains(response, "Create artifact")

    def test_create_asset_artifact_post_name_error(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        location_asset = self._force_location_asset()
        asset = location_asset.asset
        artifact = Artifact.objects.create(
            name=get_random_string(12),
            type="Profile",
            channel="Device",
            platforms=["macOS"]
        )
        response = self.client.post(reverse("mdm:create_asset_artifact", args=(asset.pk,)),
                                    {"name": artifact.name,
                                     "location_asset": location_asset.pk,
                                     "associated_domains": ["un.deux.fr", "ein.zwei.de"],
                                     "associated_domains_enable_direct_downloads": "on",
                                     "removable": "on",
                                     "vpn_uuid": str(uuid.uuid4()),
                                     "content_filter_uuid": str(uuid.uuid4()),
                                     "dns_proxy_uuid": str(uuid.uuid4()),
                                     "configuration": plistlib.dumps({"yolo": "fomo"}).decode("utf-8"),
                                     "remove_on_unenroll": "on",
                                     "prevent_backup": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        self.assertFormError(response.context["form"], "name", "An artifact with this name already exists")

    def test_create_asset_artifact_post_invalid_plist(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        location_asset = self._force_location_asset()
        asset = location_asset.asset
        response = self.client.post(reverse("mdm:create_asset_artifact", args=(asset.pk,)),
                                    {"name": get_random_string(12),
                                     "location_asset": location_asset.pk,
                                     "associated_domains": ["un.deux.fr", "ein.zwei.de"],
                                     "associated_domains_enable_direct_downloads": "on",
                                     "removable": "on",
                                     "vpn_uuid": str(uuid.uuid4()),
                                     "content_filter_uuid": str(uuid.uuid4()),
                                     "dns_proxy_uuid": str(uuid.uuid4()),
                                     "configuration": "yolo",
                                     "remove_on_unenroll": "on",
                                     "prevent_backup": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        self.assertFormError(response.context["form"], "configuration", "Invalid property list")

    def test_create_asset_artifact_post_plist_not_a_dict(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        location_asset = self._force_location_asset()
        asset = location_asset.asset
        response = self.client.post(reverse("mdm:create_asset_artifact", args=(asset.pk,)),
                                    {"name": get_random_string(12),
                                     "location_asset": location_asset.pk,
                                     "associated_domains": ["un.deux.fr", "ein.zwei.de"],
                                     "associated_domains_enable_direct_downloads": "on",
                                     "removable": "on",
                                     "vpn_uuid": str(uuid.uuid4()),
                                     "content_filter_uuid": str(uuid.uuid4()),
                                     "dns_proxy_uuid": str(uuid.uuid4()),
                                     "configuration": plistlib.dumps(["un"]).decode("utf-8"),
                                     "remove_on_unenroll": "on",
                                     "prevent_backup": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        self.assertFormError(response.context["form"], "configuration", "Not a dictionary")

    def test_create_asset_artifact_post(self):
        self._login("mdm.view_asset", "mdm.add_artifact", "mdm.view_artifact")
        location_asset = self._force_location_asset()
        asset = location_asset.asset
        name = get_random_string(12)
        response = self.client.post(reverse("mdm:create_asset_artifact", args=(asset.pk,)),
                                    {"name": name,
                                     "location_asset": location_asset.pk,
                                     "associated_domains": ["un.deux.fr", "ein.zwei.de"],
                                     "associated_domains_enable_direct_downloads": "on",
                                     "removable": "on",
                                     "vpn_uuid": str(uuid.uuid4()),
                                     "content_filter_uuid": str(uuid.uuid4()),
                                     "dns_proxy_uuid": str(uuid.uuid4()),
                                     "configuration": "<dict><key>un</key><integer>1</integer></dict>",
                                     "remove_on_unenroll": "on",
                                     "prevent_backup": "on"},
                                    follow=True)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.name, name)
        self.assertEqual(artifact.artifactversion_set.count(), 1)
        artifact_version = artifact.artifactversion_set.first()
        store_app = StoreApp.objects.get(artifact_version=artifact_version, location_asset=location_asset)
        self.assertEqual(store_app.get_management_flags(), 5)
        self.assertTrue(store_app.has_configuration())
        self.assertEqual(store_app.get_configuration(), {"un": 1})

    def test_create_asset_artifact_get_default_name_collision_avoided(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        location_asset = self._force_location_asset()
        asset = location_asset.asset
        for i in range(0, 4):
            if i > 0:
                suffix = f" ({i})"
            else:
                suffix = ""
            Artifact.objects.create(
                name=f"{asset.name}{suffix}",
                type="Profile",
                channel="Device",
                platforms=["macOS"]
            )

        response = self.client.get(reverse("mdm:create_asset_artifact", args=(asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        form = response.context["form"]
        self.assertEqual(form.fields["name"].initial, f"{asset.name} (4)")

    def test_create_asset_artifact_get_default_name_collision(self):
        self._login("mdm.view_asset", "mdm.add_artifact")
        asset = self._force_asset()
        for i in range(0, 11):
            if i > 0:
                suffix = f" ({i})"
            else:
                suffix = ""
            Artifact.objects.create(
                name=f"{asset.name}{suffix}",
                type="Profile",
                channel="Device",
                platforms=["macOS"]
            )

        response = self.client.get(reverse("mdm:create_asset_artifact", args=(asset.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/assetartifact_form.html")
        form = response.context["form"]
        self.assertEqual(form.fields["name"].initial, asset.name)

    # upgrade store app get

    def test_upgrade_store_app_get_redirect(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self._login_redirect(reverse("mdm:upgrade_store_app", args=(artifact.pk,)))

    def test_upgrade_store_app_get_permission_denied(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self._login("mdm.change_artifactversion")
        response = self.client.get(reverse("mdm:upgrade_store_app", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_upgrade_store_app_get_ok(self):
        artifact, _ = force_artifact(artifact_type=Artifact.Type.STORE_APP)
        self._login("mdm.add_artifactversion")
        response = self.client.get(reverse("mdm:upgrade_store_app", args=(artifact.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")

    # upgrade store app post

    def test_upgrade_store_app_post_ok(self):
        blueprint_artifact, artifact, (store_app_av1,) = force_blueprint_artifact(
                artifact_type=Artifact.Type.STORE_APP
        )
        blueprint = blueprint_artifact.blueprint
        artifact_pk = str(artifact.pk)
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            list(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            [str(store_app_av1.pk)]
        )
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_store_app", args=(artifact.pk,)),
                                    {"default_shard": 1,
                                     "shard_modulo": 10,
                                     "macos": "on",
                                     "macos_min_version": "13.3.1",
                                     "remove_on_unenroll": False},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifactversion_detail.html")
        store_app_av2 = response.context["object"]
        self.assertEqual(artifact, store_app_av2.artifact)
        self.assertEqual(artifact.artifactversion_set.count(), 2)
        self.assertEqual(store_app_av2.version, 2)
        self.assertEqual(store_app_av2.default_shard, 1)
        self.assertEqual(store_app_av2.shard_modulo, 10)
        self.assertTrue(store_app_av2.macos)
        self.assertEqual(store_app_av2.macos_min_version, "13.3.1")
        store_app_2 = store_app_av2.store_app
        self.assertFalse(store_app_2.remove_on_unenroll)
        blueprint.refresh_from_db()
        # blueprint serialized artifacts updated
        self.assertEqual(list(blueprint.serialized_artifacts.keys()), [artifact_pk])
        self.assertEqual(
            set(str(av["pk"]) for av in blueprint.serialized_artifacts[artifact_pk]["versions"]),
            {str(store_app_av1.pk), str(store_app_av2.pk)}
        )

    def test_upgrade_store_app_post_no_change(self):
        _, artifact, (store_app_av1,) = force_blueprint_artifact(artifact_type=Artifact.Type.STORE_APP)
        store_app_1 = store_app_av1.store_app
        store_app_1.configuration = plistlib.dumps({"un": 1})
        store_app_1.save()
        self._login("mdm.add_artifactversion", "mdm.view_artifactversion")
        response = self.client.post(reverse("mdm:upgrade_store_app", args=(artifact.pk,)),
                                    {"default_shard": 1,
                                     "shard_modulo": 10,
                                     "macos": "on",
                                     "configuration": store_app_1.configuration.decode("utf-8"),
                                     "macos_min_version": "13.3.1",
                                     "remove_on_unenroll": True},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_upgrade_form.html")
        self.assertFormError(response.context["object_form"], None,
                             "This version of the store app is identical to the latest version")
