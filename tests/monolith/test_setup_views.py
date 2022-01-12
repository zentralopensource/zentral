from datetime import datetime
from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.monolith.models import (Catalog, Enrollment, EnrolledMachine,
                                             Manifest, ManifestCatalog, PkgInfo, PkgInfoName)
from zentral.contrib.munki.models import ManagedInstall


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MonolithSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()
        # manifest
        cls.manifest = Manifest.objects.create(meta_business_unit=cls.mbu, name=get_random_string())
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
        cls.serial_number = get_random_string()
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

    # PPDs

    def test_ppds_login_redirect(self):
        self._login_redirect(reverse("monolith:ppds"))

    def test_ppds_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:ppds"))
        self.assertEqual(response.status_code, 403)

    def test_ppds(self):
        self._login("monolith.view_printerppd")
        response = self.client.get(reverse("monolith:ppds"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/printerppd_list.html")

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

    # sub manifests

    def test_sub_manifests_login_redirect(self):
        self._login_redirect(reverse("monolith:sub_manifests"))

    def test_sub_manifests_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 403)

    def test_sub_manifests(self):
        self._login("monolith.view_submanifest")
        response = self.client.get(reverse("monolith:sub_manifests"))
        self.assertEqual(response.status_code, 200)

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
        name = get_random_string()
        response = self.client.post(reverse("monolith:create_sub_manifest"),
                                    {"name": name},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "monolith/sub_manifest.html")
        self.assertEqual(response.context["object"].name, name)

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

    # manifest machine info

    def test_manifest_machine_info_redirect(self):
        self._login_redirect(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                             + "?serial_number=" + self.serial_number)

    def test_manifest_machine_info_permission_denied(self):
        self._login()
        response = self.client.get(reverse("monolith:manifest_machine_info", args=(self.manifest.pk,))
                                   + "?serial_number=" + self.serial_number)
        self.assertEqual(response.status_code, 403)

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
