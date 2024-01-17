from datetime import datetime
import plistlib
from unittest.mock import call, Mock
from django.db.models.expressions import CombinedExpression
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.monolith.models import PkgInfo, PkgInfoCategory, PkgInfoName
from zentral.contrib.monolith.repository_backends import load_repository_backend
from zentral.core.events.base import AuditEvent
from .utils import force_catalog, force_manifest, force_pkg_info, force_repository


class MonolithRepositoriesTestCase(TestCase):
    maxDiff = None

    # utility methods

    def _build_plist(self, data):
        return plistlib.dumps(data)

    def _load_repository(self, db_repository, return_value):
        repository = load_repository_backend(db_repository)
        repository.get_icon_hashes_content = Mock(
            name="get_icon_hashes_content",
            return_value=self._build_plist({})
        )
        repository.iter_client_resources = Mock(
            name="iter_client_resources",
            return_value=[]
        )
        repository.get_all_catalog_content = Mock(
            name="get_all_catalog_content",
            return_value=self._build_plist(return_value)
        )
        return repository

    # sync catalogs

    def test_sync_catalogs(self):
        db_repository = force_repository()
        manifest = force_manifest()
        catalog = force_catalog(repository=db_repository, manifest=manifest)
        m_prev_value = manifest.serialize_for_event()
        self.assertEqual(manifest.version, 1)
        category_name = get_random_string(12)
        name = get_random_string(12)
        requires_pin_name = get_random_string(12)
        update_for_pin_name = get_random_string(12)
        now = datetime.utcnow()
        audit_callback = Mock()
        repository = self._load_repository(
            db_repository,
            [{"catalogs": [catalog.name],
              "name": name,
              "category": category_name,
              "requires": [requires_pin_name],
              "update_for": [update_for_pin_name],
              "version": "3.0",
              "yolo": now}]
        )
        repository.sync_catalogs(audit_callback)
        pkg_info = PkgInfo.objects.get(name__name=name, version="3.0")
        pin = PkgInfoName.objects.get(name=name)
        category = PkgInfoCategory.objects.get(repository=db_repository, name=category_name)
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

    def test_missing_catalog(self):
        db_repository = force_repository()
        audit_callback = Mock()
        repository = self._load_repository(
            db_repository,
            [{"name": get_random_string(12),
              "version": "1.0"}]
        )
        repository.sync_catalogs(audit_callback)
        self.assertEqual(len(audit_callback.call_args_list), 0)

    def test_sync_catalogs_catalog_updates(self):
        db_repository = force_repository()
        old_catalog = force_catalog(repository=db_repository)
        oc_prev_value = old_catalog.serialize_for_event()
        pkg_info = force_pkg_info(catalog=old_catalog)
        pi_prev_value = pkg_info.serialize_for_event()
        manifest = force_manifest()
        m_prev_value = manifest.serialize_for_event()
        new_catalog = force_catalog(repository=db_repository, manifest=manifest, archived=True)
        nc_prev_value = new_catalog.serialize_for_event()
        audit_callback = Mock()
        repository = self._load_repository(
            db_repository,
            [{"catalogs": [new_catalog.name],
              "name": pkg_info.name.name,
              "version": "1.0"}]
        )
        repository.sync_catalogs(audit_callback)
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

    def test_sync_catalogs_pkg_info_archived(self):
        db_repository = force_repository()
        rpita_catalog = force_catalog(repository=db_repository)
        rpitac_prev_value = rpita_catalog.serialize_for_event()
        remote_pkg_info_to_archive = force_pkg_info(catalog=rpita_catalog, local=False)
        rpita_prev_value = remote_pkg_info_to_archive.serialize_for_event()
        new_name = get_random_string(12)
        manifest = force_manifest()
        m_prev_value = manifest.serialize_for_event()
        new_catalog = force_catalog(repository=db_repository, manifest=manifest)
        audit_callback = Mock()
        repository = load_repository_backend(db_repository)
        repository = self._load_repository(
            db_repository,
            [{"catalogs": [new_catalog.name],
              "name": new_name,
              "version": "3.0"}]
        )
        repository.sync_catalogs(audit_callback)
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

    def test_sync_catalogs_pkg_info_unarchived(self):
        db_repository = force_repository()
        manifest = force_manifest()
        manifest_prev_value = manifest.serialize_for_event()
        catalog = force_catalog(repository=db_repository, manifest=manifest)
        pkg_info_to_unarchive = force_pkg_info(local=False, catalog=catalog, archived=True)
        self.assertIsNotNone(pkg_info_to_unarchive.archived_at)
        prev_value = pkg_info_to_unarchive.serialize_for_event()
        audit_callback = Mock()
        repository = load_repository_backend(db_repository)
        repository = self._load_repository(
            db_repository,
            [{"catalogs": [catalog.name],
              "name": pkg_info_to_unarchive.name.name,
              "version": pkg_info_to_unarchive.version}]
        )
        repository.sync_catalogs(audit_callback)
        # pkg_info_to_unarchive archived at is None, because present in the catalog
        pkg_info_to_unarchive.refresh_from_db()
        self.assertIsNone(pkg_info_to_unarchive.archived_at)
        self.assertEqual(
            audit_callback.call_args_list,
            [call(pkg_info_to_unarchive, AuditEvent.Action.UPDATED, prev_value),
             call(manifest, AuditEvent.Action.UPDATED, manifest_prev_value)]
        )
