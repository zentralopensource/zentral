from datetime import datetime
from functools import reduce
from io import BytesIO
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from django.utils.text import slugify
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.monolith.models import (Catalog, Condition, Enrollment, EnrolledMachine,
                                             Manifest, ManifestCatalog, PkgInfo, PkgInfoCategory, PkgInfoName,
                                             SubManifest, SubManifestPkgInfo)
from zentral.contrib.munki.models import ManagedInstall
from zentral.core.events.base import AuditEvent
from .utils import build_dummy_package


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MonolithSetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()
        # manifest
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.mbu, name=get_random_string(12))
        # catalog
        cls.catalog_1 = Catalog.objects.create(name=get_random_string(13), priority=10)
        # manifest catalog
        ManifestCatalog.objects.create(manifest=cls.manifest, catalog=cls.catalog_1)
        # pkginfo name
        cls.pkginfo_name_1 = PkgInfoName.objects.create(name="aaaa first name")
        # pkginfo
        cls.pkginfo_1_1 = PkgInfo.objects.create(name=cls.pkginfo_name_1, version="1.0",
                                                 data={"name": cls.pkginfo_name_1.name,
                                                       "version": "1.0"})
        cls.pkginfo_1_1.catalogs.set([cls.catalog_1])
        # enrollment
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.mbu)
        cls.enrollment = Enrollment.objects.create(secret=cls.enrollment_secret, manifest=cls.manifest)
        # enrolled machine
        cls.serial_number = get_random_string(12)
        cls.enrolled_machine = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                              serial_number=cls.serial_number)
        # simulate 1 install of 1v1
        ManagedInstall.objects.create(
            machine_serial_number=cls.serial_number,
            name=cls.pkginfo_name_1.name,
            installed_version=cls.pkginfo_1_1.version,
            installed_at=datetime.utcnow()
        )

    # utility methods

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

    def _force_sub_manifest(self, condition=None):
        submanifest = SubManifest.objects.create(name=get_random_string(12))
        submanifest_pkginfo = SubManifestPkgInfo.objects.create(
            sub_manifest=submanifest,
            key="managed_installs",
            pkg_info_name=self.pkginfo_name_1,
            condition=condition
        )
        return submanifest, submanifest_pkginfo

    def _force_pkg_info_name(self):
        return PkgInfoName.objects.create(name=get_random_string(12))

    def _force_pkg_info(self, local=True, version="1.0", archived=False):
        pkg_info_name = self._force_pkg_info_name()
        return PkgInfo.objects.create(
            name=pkg_info_name, version=version, local=local,
            archived_at=datetime.utcnow() if archived else None,
            data={
                "name": pkg_info_name.name,
                "version": version
            }
        )

    # pkg infos

    def test_pkg_infos_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_infos"))

    def test_pkg_infos_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:pkg_infos"))
        self.assertEqual(response.status_code, 403)

    def test_pkg_infos(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_infos"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkg_info_list.html")
        self.assertContains(response, self.pkginfo_name_1.name)

    # pkg info name

    def test_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name(self):
        self._login("monolith.view_pkginfoname", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        self.assertContains(response, self.pkginfo_name_1.name)

    def test_pkg_info_name_events_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_fetch_events_login_redirect(self):
        self._login_redirect(reverse("monolith:fetch_pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_events_store_redirect_login_redirect(self):
        self._login_redirect(reverse("monolith:pkg_info_name_events_store_redirect", args=(self.pkginfo_name_1.pk,)))

    def test_pkg_info_name_events_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name_fetch_events_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:fetch_pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_pkg_info_name_events_store_redirect_permission_denied(self):
        self._login("monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:pkg_info_name_events_store_redirect",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_pkg_info_name_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/pkg_info_name_events.html")

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_pkg_info_name_fetch_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:fetch_pkg_info_name_events",
                                   args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_pkg_info_name_events_store_redirect(self):
        self._login("monolith.view_pkginfo", "monolith.view_pkginfoname")
        response = self.client.get(reverse("monolith:pkg_info_name_events_store_redirect",
                                   args=(self.pkginfo_name_1.pk,)))
        # dev store cannot redirect
        self.assertRedirects(response, reverse("monolith:pkg_info_name_events", args=(self.pkginfo_name_1.pk,)))

    # create pkg info name

    def test_create_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:create_pkg_info_name"))

    def test_create_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_pkg_info_name"))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_pkg_info_name(self, post_event):
        self._login("monolith.add_pkginfoname", "monolith.view_pkginfoname")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:create_pkg_info_name"), {"name": name}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        self.assertContains(response, name)
        pkg_info_name = response.context["object"]
        self.assertEqual(pkg_info_name.name, name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfoname",
                 "pk": str(pkg_info_name.pk),
                 "new_value": {
                     "pk": pkg_info_name.pk,
                     "name": name,
                     "created_at": pkg_info_name.created_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_pkginfo_name": [name]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # delete pkg info name

    def test_delete_pkg_info_name_login_redirect(self):
        self._login_redirect(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))

    def test_delete_pkg_info_name_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_pkg_info_name_404(self):
        self._login("monolith.delete_pkginfoname")
        response = self.client.post(reverse("monolith:delete_pkg_info_name", args=(self.pkginfo_name_1.pk,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_pkg_info_name(self, post_event):
        self._login("monolith.delete_pkginfoname", "monolith.view_pkginfo")
        pkg_info_name = self._force_pkg_info_name()
        prev_pk = pkg_info_name.pk
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("monolith:delete_pkg_info_name", args=(pkg_info_name.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_list.html")
        self.assertNotContains(response, pkg_info_name.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "monolith.pkginfoname",
                 "pk": str(prev_pk),
                 "prev_value": {
                     "pk": prev_pk,
                     "name": pkg_info_name.name,
                     "created_at": pkg_info_name.created_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_pkginfo_name": [pkg_info_name.name]})
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # upload package

    def test_upload_package_login_redirect(self):
        self._login_redirect(reverse("monolith:upload_package"))

    def test_upload_package_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:upload_package"))
        self.assertEqual(response.status_code, 403)

    def test_upload_package_get_no_name(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = self._force_pkg_info_name()
        response = self.client.get(reverse("monolith:upload_package"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        choices = list(response.context["form"].fields["name"].queryset.all())
        self.assertEqual(set(choices), {pkg_info_name, self.pkginfo_name_1})

    def test_upload_package_get_name(self):
        self._login("monolith.add_pkginfo")
        pkg_info_name = self._force_pkg_info_name()
        response = self.client.get(reverse("monolith:upload_package"), {"pin_id": pkg_info_name.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertNotIn("name", response.context["form"].fields)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        pkg_info_name = self._force_pkg_info_name()
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("monolith:upload_package"),
                {"file": file,
                 "name": pkg_info_name.pk,
                 "catalogs": [self.catalog_1.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        self.assertEqual(pkg_info.data["installer_item_location"], file.name)
        self.assertEqual(pkg_info.data["name"], pkg_info_name.name)
        self.assertEqual(
            pkg_info.data["receipts"],
            [{'installed_size': 0,
              'packageid': 'io.zentral.test123',
              'version': '1.0'}]
        )
        self.assertEqual(pkg_info.data["version"], "1.0")
        self.assertEqual(pkg_info.version, "1.0")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event_payload_data = event.payload["object"]["new_value"].pop("data")
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "catalogs":  [{"pk": self.catalog_1.pk, "name": self.catalog_1.name}],
                     "requires": [],
                     "update_for": [],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        self.assertEqual(event_payload_data["name"], pkg_info_name.name)
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package_from_pkg_info_name(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        pkg_info_category = PkgInfoCategory.objects.create(name=get_random_string(12))
        pkg_info_name = self._force_pkg_info_name()
        pkg_info_name_required = self._force_pkg_info_name()
        pkg_info_name_update_for = self._force_pkg_info_name()
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        shard_tag = Tag.objects.create(name=get_random_string(12))
        file = BytesIO(build_dummy_package())
        file.name = "test123.pkg"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                "{}?pin_id={}".format(reverse("monolith:upload_package"), pkg_info_name.pk),
                {"file": file,
                 "display_name": "Yolo",
                 "description": "Fomo",
                 "catalogs": [self.catalog_1.pk],
                 "category": pkg_info_category.pk,
                 "requires": [pkg_info_name_required.pk],
                 "update_for": [pkg_info_name_update_for.pk],
                 "excluded_tags": [excluded_tag.pk],
                 "shard_modulo": 5,
                 "default_shard": 2,
                 f"tag-shard-{shard_tag.pk}": 5},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        data = {
            'name': pkg_info_name.name,
            'version': '1.0',
            'category': pkg_info_category.name,
            'receipts': [{'version': '1.0',
                          'packageid': 'io.zentral.test123',
                          'installed_size': 0}],
            'requires': [pkg_info_name_required.name],
            'autoremove': False,
            'update_for': [pkg_info_name_update_for.name],
            'description': 'Fomo',
            'display_name': 'Yolo',
            'uninstallable': True,
            'installed_size': 0,
            'uninstall_method': 'removepackages',
            'zentral_monolith': {
                'shards': {
                    'tags': {
                        shard_tag.name: 5
                    },
                    'modulo': 5,
                    'default': 2
                 },
                'excluded_tags': [excluded_tag.name]
            },
            'minimum_os_version': '10.11.0',
            'unattended_install': True,
            'installer_item_size': 2,
            'installer_item_hash': pkg_info.data["installer_item_hash"],
            'unattended_uninstall': True,
            'installer_item_location': 'test123.pkg'
        }
        self.assertEqual(pkg_info.data, data)
        self.assertEqual(pkg_info.version, "1.0")
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "category": {"name": pkg_info_category.name, "pk": pkg_info_category.pk},
                     "catalogs":  [{"pk": self.catalog_1.pk, "name": self.catalog_1.name}],
                     "data": data,
                     "requires": [pkg_info_name_required.name],
                     "update_for": [pkg_info_name_update_for.name],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    def test_upload_package_conflict(self):
        self._login("monolith.add_pkginfo")
        pkg_info = self._force_pkg_info()
        file = BytesIO(build_dummy_package(name=pkg_info.name.name, version=pkg_info.version))
        file.name = "{}.pkg".format(get_random_string(12))
        response = self.client.post(
            reverse("monolith:upload_package"),
            {"file": file,
             "name": pkg_info.name.pk,
             "catalogs": [self.catalog_1.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/package_form.html")
        self.assertFormError(
            response, "form", "file",
            "A PkgInfo with the same name and version already exists."
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_package_existing_archived_package(self, post_event):
        self._login("monolith.add_pkginfo", "monolith.view_pkginfoname", "monolith.view_pkginfo")
        pkg_info = self._force_pkg_info(archived=True)
        pkg_info_name = pkg_info.name
        file = BytesIO(build_dummy_package(pkg_info_name.name, pkg_info.version))
        file.name = "{}.pkg".format(get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("monolith:upload_package"),
                {"file": file,
                 "name": pkg_info_name.pk,
                 "catalogs": [self.catalog_1.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "monolith/pkg_info_name.html")
        pkg_info = pkg_info_name.pkginfo_set.first()
        self.assertTrue(pkg_info.local is True)
        self.assertEqual(pkg_info.file.name, f"monolith/packages/{pkg_info.pk:08d}.pkg")
        self.assertEqual(pkg_info.data["installer_item_location"], file.name)
        self.assertEqual(pkg_info.data["name"], pkg_info_name.name)
        self.assertEqual(
            pkg_info.data["receipts"],
            [{'installed_size': 0,
              'packageid': 'io.zentral.{}'.format(slugify(pkg_info_name.name)),
              'version': '1.0'}]
        )
        self.assertEqual(pkg_info.data["version"], "1.0")
        self.assertEqual(pkg_info.version, "1.0")
        self.assertIsNone(pkg_info.archived_at)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        event_payload_data = event.payload["object"]["new_value"].pop("data")
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "monolith.pkginfo",
                 "pk": str(pkg_info.pk),
                 "new_value": {
                     "pk": pkg_info.pk,
                     "local": True,
                     "name": pkg_info_name.name,
                     "catalogs":  [{"pk": self.catalog_1.pk, "name": self.catalog_1.name}],
                     "requires": [],
                     "update_for": [],
                     "version": "1.0",
                     "created_at": pkg_info.created_at,
                     "updated_at": pkg_info.updated_at,
                 }
              }}
        )
        self.assertEqual(event_payload_data["name"], pkg_info_name.name)
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["objects"],
            {"munki_pkginfo": [f"{pkg_info_name.name}|1.0"],
             "munki_pkginfo_name": [pkg_info_name.name]}
        )
        self.assertEqual(sorted(metadata["tags"]), ["monolith", "zentral"])

    # catalogs

    def test_catalogs_login_redirect(self):
        self._login_redirect(reverse("monolith:catalogs"))

    def test_catalogs_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:catalogs"))
        self.assertEqual(response.status_code, 403)

    def test_catalogs(self):
        self._login("monolith.view_catalog")
        response = self.client.get(reverse("monolith:catalogs"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/catalog_list.html")

    # conditions

    def test_conditions_login_redirect(self):
        self._login_redirect(reverse("monolith:conditions"))

    def test_conditions_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:conditions"))
        self.assertEqual(response.status_code, 403)

    def test_conditions(self):
        self._login("monolith.view_condition")
        response = self.client.get(reverse("monolith:conditions"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_list.html")

    def test_condition_login_redirect(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login_redirect(reverse("monolith:condition", args=(condition.pk,)))

    def test_condition_permission_denied(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login()
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_condition(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.view_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertNotContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_condition_with_delete(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_condition_cannot_delete(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        submanifest, _ = self._force_sub_manifest(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, condition.name)
        self.assertNotContains(response, reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_delete_condition_login_redirect(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login_redirect(reverse("monolith:delete_condition", args=(condition.pk,)))

    def test_delete_condition_permission_denied(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login()
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_condition_get(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.delete_condition")
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_confirm_delete.html")

    def test_delete_condition_post(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.post(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_list.html")
        self.assertEqual(Condition.objects.filter(pk=condition.pk).count(), 0)

    def test_delete_condition_get_blocked(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        submanifest, _ = self._force_sub_manifest(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.get(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, "cannot be deleted")

    def test_delete_condition_post_blocked(self):
        condition = Condition.objects.create(name=get_random_string(12), predicate='machine_type == "laptop"')
        submanifest, _ = self._force_sub_manifest(condition=condition)
        self._login("monolith.view_condition", "monolith.delete_condition")
        response = self.client.post(reverse("monolith:delete_condition", args=(condition.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/condition_detail.html")
        self.assertContains(response, "cannot be deleted")

    # sub manifests

    def test_sub_manifests_login_redirect(self):
        self._login_redirect(reverse("monolith:sub_manifests"))

    def test_sub_manifests_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_sub_manifests(self):
        self._login("monolith.view_submanifest")
        submanifest, _ = self._force_sub_manifest()
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, submanifest.name)

    # sub manifest

    def test_sub_manifest_login_redirect(self):
        submanifest, _ = self._force_sub_manifest()
        self._login_redirect(reverse("monolith:sub_manifest", args=(submanifest.pk,)))

    def test_sub_manifest_permission_denied(self):
        submanifest, _ = self._force_sub_manifest()
        self._login()
        response = self.client.get(reverse("monolith:sub_manifest", args=(submanifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_sub_manifest_no_pkginfo_edit_link(self):
        submanifest, submanifest_pkginfo = self._force_sub_manifest()
        self._login("monolith.view_submanifest")
        response = self.client.get(reverse("monolith:sub_manifest", args=(submanifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(submanifest.pk, submanifest_pkginfo.pk))
        )

    def test_sub_manifest_pkginfo_edit_link(self):
        submanifest, submanifest_pkginfo = self._force_sub_manifest()
        self._login("monolith.view_submanifest", "monolith.change_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(submanifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertNotContains(response, 'class="danger"')
        self.assertContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(submanifest.pk, submanifest_pkginfo.pk))
        )

    def test_sub_manifest_pkginfo_archived_no_edit_link(self):
        submanifest, submanifest_pkginfo = self._force_sub_manifest()
        self.pkginfo_1_1.archived_at = datetime.utcnow()
        self.pkginfo_1_1.save()
        self._login("monolith.view_submanifest", "monolith.change_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest", args=(submanifest.pk,)))
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertContains(response, 'class="danger"')
        self.assertNotContains(
            response,
            reverse("monolith:update_sub_manifest_pkg_info",
                    args=(submanifest.pk, submanifest_pkginfo.pk))
        )

    # create submanifest

    def test_create_submanifest_redirect(self):
        self._login_redirect(reverse("monolith:create_sub_manifest"))

    def test_create_submanifest_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:create_sub_manifest"))
        self.assertEqual(response.status_code, 403)

    def test_create_submanifest_get(self):
        self._login("monolith.add_submanifest")
        response = self.client.get(reverse("monolith:create_sub_manifest"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest.html")

    def test_create_submanifest_post(self):
        self._login("monolith.add_submanifest", "monolith.view_submanifest")
        name = get_random_string(12)
        response = self.client.post(reverse("monolith:create_sub_manifest"),
                                    {"name": name},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertEqual(response.context["object"].name, name)

    # add submanifest pkginfo

    def test_add_sub_manifest_pkg_info_redirect(self):
        submanifest, _ = self._force_sub_manifest()
        self._login_redirect(reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)))

    def test_add_sub_manifest_pkg_info_permission_denied(self):
        submanifest, _ = self._force_sub_manifest()
        self._login()
        response = self.client.get(reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_add_sub_manifest_pkg_info_get(self):
        submanifest, _ = self._force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo")
        response = self.client.get(reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")

    def test_add_sub_manifest_pkg_info_post_pkg_info_name_already_included(self):
        submanifest, _ = self._force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo")
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)),
            {"pkg_info_name": self.pkginfo_name_1.pk,
             "key": "managed_installs"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")
        self.assertFormError(
            response, "form", "pkg_info_name",
            "Select a valid choice. That choice is not one of the available choices."
        )

    def test_add_sub_manifest_pkg_info_post_featured_item_error(self):
        submanifest, _ = self._force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo")
        pkginfo_name = PkgInfoName.objects.create(name=get_random_string(12))
        PkgInfo.objects.create(name=pkginfo_name, version="1.0",
                               data={"name": pkginfo_name.name,
                                     "version": "1.0"})
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)),
            {"pkg_info_name": pkginfo_name.pk,
             "key": "managed_installs",
             "featured_item": "on"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/edit_sub_manifest_pkg_info.html")
        self.assertFormError(response, "form", "featured_item", "Only optional install items can be featured")

    def test_add_sub_manifest_pkg_info_post(self):
        submanifest, _ = self._force_sub_manifest()
        self._login("monolith.add_submanifestpkginfo", "monolith.view_submanifest")
        pkginfo_name = PkgInfoName.objects.create(name=get_random_string(12))
        PkgInfo.objects.create(name=pkginfo_name, version="1.0",
                               data={"name": pkginfo_name.name,
                                     "version": "1.0"})
        response = self.client.post(
            reverse("monolith:sub_manifest_add_pkg_info", args=(submanifest.pk,)),
            {"pkg_info_name": pkginfo_name.pk,
             "key": "optional_installs",
             "featured_item": "on"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertContains(response, pkginfo_name.name)

    # manifests

    def test_manifests_login_redirect(self):
        self._login_redirect(reverse("monolith:manifests"))

    def test_manifests_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifests"))
        self.assertEqual(response.status_code, 403)

    def test_manifests(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:manifests"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest_list.html")
        self.assertEqual(response.context["object_list"][0], self.manifest)

    # manifest

    def test_manifest_login_redirect(self):
        self._login_redirect(reverse("monolith:manifest", args=(self.manifest.pk,)))

    def test_manifest_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_manifest(self):
        self._login("monolith.view_manifest")
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        self.assertEqual(response.context["object"], self.manifest)
        self.assertNotContains(
            response, reverse("monolith_api:enrollment_plist", args=(self.enrollment.pk,)))
        self.assertNotContains(
            response, reverse("monolith_api:enrollment_configuration_profile", args=(self.enrollment.pk,)))

    def test_manifest_with_enrollments(self):
        self._login("monolith.view_manifest", "monolith.view_enrollment")
        response = self.client.get(reverse("monolith:manifest", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/manifest.html")
        self.assertEqual(response.context["object"], self.manifest)
        self.assertContains(
            response, reverse("monolith_api:enrollment_plist", args=(self.enrollment.pk,)))
        self.assertContains(
            response, reverse("monolith_api:enrollment_configuration_profile", args=(self.enrollment.pk,)))

    # manifest machine info

    def test_manifest_machine_info_redirect(self):
        self._login_redirect(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                             + "?serial_number=" + self.serial_number)

    def test_manifest_machine_info_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                                   + "?serial_number=" + self.serial_number)
        self.assertEqual(response.status_code, 403)

    def test_manifest_machine_info_not_found(self):
        self._login("monolith.view_manifest", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_manifest_machine_info(self):
        self._login("monolith.view_manifest", "monolith.view_pkginfo")
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                                   + "?serial_number=" + self.serial_number)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/machine_info.html")
        self.assertEqual(response.context["machine"].serial_number, self.serial_number)
        self.assertEqual(
            response.context["packages"],
            [('aaaa first name',
              {'pkgsinfo': [({'name': 'aaaa first name', 'version': '1.0'},
                             'installed',
                             [],
                             None,
                             None,
                             [],
                             True)]})]
        )
