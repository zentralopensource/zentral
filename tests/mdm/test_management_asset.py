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
from zentral.contrib.mdm.models import Artifact, Asset, Location, LocationAsset, StoreApp


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

    def _force_asset(self):
        return Asset.objects.create(
            adam_id=get_random_string(12, allowed_chars="0123456789"),
            pricing_param=get_random_string(12),
            product_type=Asset.ProductType.APP,
            device_assignable=True,
            revocable=True,
            supported_platforms=["iOS", "macOS"],
            name=get_random_string(12),
            bundle_id="pro.zentral.tests"
        )

    def _force_location_asset(self):
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
        return LocationAsset.objects.create(
            asset=asset,
            location=location
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
        self.assertFormError(response, "form", "name", "An artifact with this name already exists")

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
        self.assertFormError(response, "form", "configuration", "Invalid property list")

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
        self.assertFormError(response, "form", "configuration", "Not a dictionary")

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
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/artifact_detail.html")
        artifact = response.context["object"]
        self.assertEqual(artifact.name, name)
        store_app = StoreApp.objects.get(artifact_version__artifact=artifact, location_asset=location_asset)
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
