from datetime import datetime
import plistlib
from unittest.mock import call, patch, Mock
from django.db.models.expressions import CombinedExpression
from django.http import HttpResponseRedirect
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.monolith.conf import monolith_conf
from zentral.contrib.monolith.exceptions import RepositoryError
from zentral.contrib.monolith.models import Catalog, PkgInfoCategory, Manifest, ManifestCatalog, PkgInfo, PkgInfoName
from zentral.contrib.monolith.repository_backends.http import Repository as HttpRepository
from zentral.core.events.base import AuditEvent


class MonolithRepositoriesTestCase(TestCase):
    maxDiff = None

    # utility methods

    def _build_all_catalog(self, data):
        return plistlib.dumps(data)

    def _force_catalog(self, archived=False):
        catalog = Catalog.objects.create(
            name=get_random_string(12),
            archived_at=datetime.utcnow() if archived else None,
        )
        ManifestCatalog.objects.create(
            manifest=Manifest.objects.create(
                meta_business_unit=MetaBusinessUnit.objects.create(name=get_random_string(12)),
                name=get_random_string(12)
            ),
            catalog=catalog
        )
        return catalog

    def _force_category(self):
        return PkgInfoCategory.objects.create(name=get_random_string(12))

    def _force_name(self):
        return PkgInfoName.objects.create(name=get_random_string(12))

    def _force_pkg_info(self, local=True, version="1.0", archived=False, alles=False):
        pkg_info_name = self._force_name()
        data = {"name": pkg_info_name.name,
                "version": version}
        pi = PkgInfo.objects.create(
            name=pkg_info_name, version=version, local=local,
            archived_at=datetime.utcnow() if archived else None,
            data=data
        )
        pi.catalogs.add(self._force_catalog())
        return pi

    # http repository

    @patch("zentral.contrib.monolith.repository_backends.http.requests.get")
    def test_http_repository_get_all_catalog_content(self, requests_get):
        mocked_r = Mock()
        mocked_r.status_code = 200
        mocked_r.content = b"yolo"
        requests_get.return_value = mocked_r
        r = HttpRepository({"root": "https://example.com/root"})
        self.assertEqual(r.get_all_catalog_content(), b"yolo")
        requests_get.assert_called_once_with("https://example.com/root/catalogs/all")

    @patch("zentral.contrib.monolith.repository_backends.http.requests.get")
    def test_http_repository_get_all_catalog_content_error(self, requests_get):
        mocked_r = Mock()
        mocked_r.status_code = 400
        requests_get.return_value = mocked_r
        r = HttpRepository({"root": "https://example.com/root"})
        with self.assertRaises(RepositoryError):
            r.get_all_catalog_content()
        requests_get.assert_called_once_with("https://example.com/root/catalogs/all")

    def test_http_repository_make_munki_response(self):
        r = HttpRepository({"root": "https://example.com/root"})
        resp = r.make_munki_repository_response("yadi", "yada")
        self.assertIsInstance(resp, HttpResponseRedirect)
        self.assertEqual(resp.headers["Location"], "https://example.com/root/yadi/yada")

    # sync catalogs

    @patch("zentral.contrib.monolith.repository_backends.local.Repository.get_all_catalog_content")
    def test_sync_catalogs(self, get_all_catalog_content):
        catalog = self._force_catalog()
        manifest = catalog.manifestcatalog_set.first().manifest
        m_prev_value = manifest.serialize_for_event()
        self.assertEqual(manifest.version, 1)
        category_name = get_random_string(12)
        name = get_random_string(12)
        requires_pin_name = get_random_string(12)
        update_for_pin_name = get_random_string(12)
        now = datetime.utcnow()
        get_all_catalog_content.return_value = self._build_all_catalog([
            {"catalogs": [catalog.name],
             "name": name,
             "category": category_name,
             "requires": [requires_pin_name],
             "update_for": [update_for_pin_name],
             "version": "3.0",
             "yolo": now}
        ])
        audit_callback = Mock()
        monolith_conf.repository.sync_catalogs(audit_callback)
        pkg_info = PkgInfo.objects.get(name__name=name, version="3.0")
        pin = PkgInfoName.objects.get(name=name)
        category = PkgInfoCategory.objects.get(name=category_name)
        requires_pin = PkgInfoName.objects.get(name=requires_pin_name)
        update_for_pin = PkgInfoName.objects.get(name=update_for_pin_name)
        self.assertEqual(
            audit_callback.call_args_list,
            [call(pin, AuditEvent.Action.CREATED),
             call(category, AuditEvent.Action.CREATED),
             call(requires_pin, AuditEvent.Action.CREATED),
             call(update_for_pin, AuditEvent.Action.CREATED),
             call(pkg_info, AuditEvent.Action.CREATED),
             call(manifest, AuditEvent.Action.UPDATED, m_prev_value)]
        )
        self.assertEqual(list(pkg_info.catalogs.all()), [catalog])
        self.assertEqual(pkg_info.name, pin)
        self.assertEqual(pkg_info.version, "3.0")
        self.assertEqual(pkg_info.category, category)
        self.assertEqual(list(pkg_info.requires.all()), [requires_pin])
        self.assertEqual(list(pkg_info.update_for.all()), [update_for_pin])
        self.assertEqual(pkg_info.data["yolo"], now.isoformat().split(".")[0])
        audit_callback_manifest = audit_callback.call_args_list[5].args[0]
        self.assertIsInstance(audit_callback_manifest.version, CombinedExpression)  # updated
        m_new_value = audit_callback_manifest.serialize_for_event()
        self.assertEqual(m_new_value["version"], 2)  # refreshed from db for JSON serialization
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    @patch("zentral.contrib.monolith.repository_backends.local.Repository.get_all_catalog_content")
    def test_missing_catalog(self, get_all_catalog_content):
        self.assertIsNone(monolith_conf.repository.default_catalog_name)
        get_all_catalog_content.return_value = self._build_all_catalog([{
            "name": get_random_string(12),
            "version": "1.0"
        }])
        audit_callback = Mock()
        monolith_conf.repository.sync_catalogs(audit_callback)
        self.assertEqual(len(audit_callback.call_args_list), 0)

    @patch("zentral.contrib.monolith.repository_backends.local.Repository.get_all_catalog_content")
    def test_sync_catalogs_existing_local_pkg_info(self, get_all_catalog_content):
        pkg_info = self._force_pkg_info(local=True)
        pi_prev_value = pkg_info.serialize_for_event()
        catalog = pkg_info.catalogs.first()
        manifest = catalog.manifestcatalog_set.first().manifest
        m_prev_value = manifest.serialize_for_event()
        self.assertEqual(manifest.version, 1)
        category = self._force_category()
        get_all_catalog_content.return_value = self._build_all_catalog([
            {"catalogs": [catalog.name],
             "name": pkg_info.name.name,
             "category": category.name,
             "version": "1.0"}
        ])
        audit_callback = Mock()
        monolith_conf.repository.sync_catalogs(audit_callback)
        self.assertEqual(
            audit_callback.call_args_list,
            [call(pkg_info, AuditEvent.Action.UPDATED, pi_prev_value),
             call(manifest, AuditEvent.Action.UPDATED, m_prev_value)]
        )
        pkg_info.refresh_from_db()
        self.assertTrue(pkg_info.local is False)
        manifest.refresh_from_db()
        self.assertEqual(manifest.version, 2)

    @patch("zentral.contrib.monolith.repository_backends.local.Repository.get_all_catalog_content")
    def test_sync_catalogs_catalog_updates(self, get_all_catalog_content):
        pkg_info = self._force_pkg_info(local=False)
        pi_prev_value = pkg_info.serialize_for_event()
        old_catalog = pkg_info.catalogs.first()
        oc_prev_value = old_catalog.serialize_for_event()
        new_catalog = self._force_catalog(archived=True)
        nc_prev_value = new_catalog.serialize_for_event()
        manifest = new_catalog.manifestcatalog_set.first().manifest
        m_prev_value = manifest.serialize_for_event()
        get_all_catalog_content.return_value = self._build_all_catalog([
            {"catalogs": [new_catalog.name],
             "name": pkg_info.name.name,
             "version": "1.0"}
        ])
        audit_callback = Mock()
        monolith_conf.repository.sync_catalogs(audit_callback)
        self.assertEqual(
            audit_callback.call_args_list,
            [call(new_catalog, AuditEvent.Action.UPDATED, nc_prev_value),
             call(pkg_info, AuditEvent.Action.UPDATED, pi_prev_value),
             call(old_catalog, AuditEvent.Action.UPDATED, oc_prev_value),
             call(manifest, AuditEvent.Action.UPDATED, m_prev_value)]
        )
        old_catalog.refresh_from_db()
        self.assertIsNotNone(old_catalog.archived_at)
        new_catalog.refresh_from_db()
        self.assertIsNone(new_catalog.archived_at)

    @patch("zentral.contrib.monolith.repository_backends.local.Repository.get_all_catalog_content")
    def test_sync_catalogs_pkg_info_archived(self, get_all_catalog_content):
        remote_pkg_info_to_archive = self._force_pkg_info(local=False)
        rpita_prev_value = remote_pkg_info_to_archive.serialize_for_event()
        rpita_catalog = remote_pkg_info_to_archive.catalogs.first()
        rpitac_prev_value = rpita_catalog.serialize_for_event()
        local_pkg_info = self._force_pkg_info(local=True)  # local, no event
        new_name = get_random_string(12)
        new_catalog = self._force_catalog()
        manifest = new_catalog.manifestcatalog_set.first().manifest
        m_prev_value = manifest.serialize_for_event()
        get_all_catalog_content.return_value = self._build_all_catalog([
            {"catalogs": [new_catalog.name],
             "name": new_name,
             "version": "3.0"}
        ])
        audit_callback = Mock()
        monolith_conf.repository.sync_catalogs(audit_callback)
        pkg_info = PkgInfo.objects.get(name__name=new_name, version="3.0")
        self.assertEqual(
            audit_callback.call_args_list,
            [call(PkgInfoName.objects.get(name=new_name), AuditEvent.Action.CREATED),
             call(pkg_info, AuditEvent.Action.CREATED),
             call(remote_pkg_info_to_archive, AuditEvent.Action.UPDATED, rpita_prev_value),
             call(rpita_catalog, AuditEvent.Action.UPDATED, rpitac_prev_value),
             call(manifest, AuditEvent.Action.UPDATED, m_prev_value)]
        )
        # remote_pkg_info_to_archive archived because not present anymore
        remote_pkg_info_to_archive.refresh_from_db()
        self.assertIsNotNone(remote_pkg_info_to_archive.archived_at)
        # rpita_catalog archived, because it only contains archived pkg_info
        # and was not present anymore
        rpita_catalog.refresh_from_db()
        self.assertIsNotNone(rpita_catalog.archived_at)
        # local_pkg_info not archived
        local_pkg_info.refresh_from_db()
        self.assertIsNone(local_pkg_info.archived_at)
