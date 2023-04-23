from datetime import datetime
import logging
import plistlib
from django.db.models import Count, Q
from zentral.contrib.monolith.models import Catalog, Manifest, PkgInfo, PkgInfoCategory, PkgInfoName
from zentral.core.events.base import AuditEvent


logger = logging.getLogger('zentral.contrib.monolith.repository_backends.base')


class BaseRepository:
    def __init__(self, config):
        self.manual_catalog_management = config.get("manual_catalog_management", False)
        if self.manual_catalog_management:
            self.default_catalog_name = config.get("default_catalog", "Not assigned").strip()
        else:
            self.default_catalog_name = None

    def _import_category(self, name, audit_callback):
        pic, created = PkgInfoCategory.objects.get_or_create(name=name)
        if created and audit_callback:
            audit_callback(pic, AuditEvent.Action.CREATED)
        return pic

    def _import_name(self, name, audit_callback):
        pin, created = PkgInfoName.objects.get_or_create(name=name)
        if created and audit_callback:
            audit_callback(pin, AuditEvent.Action.CREATED)
        return pin

    def _import_catalogs(self, pkg_info_data, audit_callback):
        catalogs = []
        if self.default_catalog_name:
            # force the catalog to the default catalog
            pkg_info_catalogs = [self.default_catalog_name]
        else:
            # take the catalogs from the pkg info data
            pkg_info_catalogs = pkg_info_data.get("catalogs", [])
        for catalog_name in pkg_info_catalogs:
            catalog_name = catalog_name.strip()
            try:
                catalog = Catalog.objects.get(name=catalog_name)
            except Catalog.DoesNotExist:
                catalog = Catalog.objects.create(name=catalog_name)
                if audit_callback:
                    audit_callback(catalog, AuditEvent.Action.CREATED)
            else:
                if catalog.archived_at:
                    if audit_callback:
                        prev_value = catalog.serialize_for_event()
                    catalog.archived_at = None
                    catalog.save()
                    if audit_callback:
                        audit_callback(catalog, AuditEvent.Action.UPDATED, prev_value)
            catalogs.append(catalog)
        return catalogs

    def _import_pkg_info(self, pkg_info_data, audit_callback):
        name = pkg_info_data['name']
        version = pkg_info_data['version']
        # catalogs
        catalogs = self._import_catalogs(pkg_info_data, audit_callback)
        if not catalogs:
            logger.warning('PKGINFO %s %s w/o catalogs', name, version)
            return catalogs, None
        # name
        pkg_info_name = self._import_name(name, audit_callback)
        # category
        pkg_info_category = None
        category_name = pkg_info_data.get('category', None)
        if category_name:
            pkg_info_category = self._import_category(category_name, audit_callback)
        # requires
        requires = [self._import_name(n, audit_callback)
                    for n in set(pkg_info_data.get('requires', []))]
        # update_for
        update_for = [self._import_name(n, audit_callback)
                      for n in set(pkg_info_data.get('update_for', []))]
        # serialize pkg_info_data
        for key, val in pkg_info_data.items():
            if isinstance(val, datetime):
                pkg_info_data[key] = val.isoformat()
        # save PkgInfo in db
        try:
            pkg_info = (PkgInfo.objects.prefetch_related("catalogs", "requires", "update_for")
                                       .select_related("category", "name")
                                       .get(name=pkg_info_name, version=version))
        except PkgInfo.DoesNotExist:
            pkg_info = PkgInfo.objects.create(name=pkg_info_name,
                                              version=version,
                                              category=pkg_info_category,
                                              data=pkg_info_data)
            pkg_info.catalogs.set(catalogs)
            pkg_info.requires.set(requires)
            pkg_info.update_for.set(update_for)
            if audit_callback:
                audit_callback(pkg_info, AuditEvent.Action.CREATED)
        else:
            updated = False
            if audit_callback:
                prev_value = pkg_info.serialize_for_event()
            # unarchive if necessary
            if pkg_info.archived_at:
                pkg_info.archived_at = None
                updated = True
            # update the local attribute
            if pkg_info.local:
                pkg_info.local = False
                updated = True
            # update category if necessary
            pkg_info_old_category = pkg_info.category
            if pkg_info_old_category != pkg_info_category:
                pkg_info.category = pkg_info_category
                updated = True
            # update data if necessary
            pkg_info_old_data = pkg_info.data
            if pkg_info_old_data != pkg_info_data:
                pkg_info.data = pkg_info_data
                updated = True
            # update m2m attributes
            pkg_info_m2m_updates = [("requires", requires),
                                    ("update_for", update_for)]
            if not self.manual_catalog_management:
                # need to update the pkg info catalogs too
                pkg_info_m2m_updates.append(("catalogs", catalogs))
            for pkg_info_attr, pkg_info_values in pkg_info_m2m_updates:
                pkg_info_old_values = set(getattr(pkg_info, pkg_info_attr).all())
                pkg_info_values = set(pkg_info_values)
                if pkg_info_old_values != pkg_info_values:
                    getattr(pkg_info, pkg_info_attr).set(pkg_info_values)
                    updated = True
            # save updates
            if updated:
                pkg_info.save()  # even if only the m2m attributes were updated, for updated_at
                if audit_callback:
                    audit_callback(pkg_info, AuditEvent.Action.UPDATED, prev_value)

        return catalogs, pkg_info

    def _archive_catalog(self, catalog, audit_callback):
        if audit_callback:
            prev_value = catalog.serialize_for_event()
        catalog.archived_at = datetime.utcnow()
        catalog.save()
        if audit_callback:
            audit_callback(catalog, AuditEvent.Action.UPDATED, prev_value)

    def _archive_pkg_info(self, pkg_info, audit_callback):
        if audit_callback:
            prev_value = pkg_info.serialize_for_event()
        pkg_info.archived_at = datetime.utcnow()
        pkg_info.save()
        if audit_callback:
            audit_callback(pkg_info, AuditEvent.Action.UPDATED, prev_value)

    def _bump_manifest(self, manifest, audit_callback):
        if audit_callback:
            prev_value = manifest.serialize_for_event()
        manifest.bump_version()
        if audit_callback:
            audit_callback(manifest, AuditEvent.Action.UPDATED, prev_value)

    def sync_catalogs(self, audit_callback=None):
        found_pkg_info_pks = set([])
        found_catalog_pks = set([])
        # update or create current pkg_infos
        for pkg_info_data in plistlib.loads(self.get_all_catalog_content()):
            catalogs, pkg_info = self._import_pkg_info(pkg_info_data, audit_callback)
            found_catalog_pks.update(c.pk for c in catalogs)
            if pkg_info:
                found_pkg_info_pks.add(pkg_info.pk)
        # archive unknown non-local pkg_infos
        for pkg_info in (PkgInfo.objects.prefetch_related("catalogs", "requires", "update_for")
                                        .select_related("category", "name")
                                        .filter(archived_at__isnull=True)
                                        .exclude(Q(local=True) | Q(pk__in=found_pkg_info_pks))):
            self._archive_pkg_info(pkg_info, audit_callback)
        # archive old catalogs if auto catalog management
        if not self.manual_catalog_management:
            for c in (Catalog.objects.annotate(pkginfo_count=Count("pkginfo",
                                                                   filter=Q(pkginfo__archived_at__isnull=True)))
                                     .filter(archived_at__isnull=True, pkginfo_count=0)
                                     .exclude(pk__in=found_catalog_pks)):
                self._archive_catalog(c, audit_callback)
        # bump versions of manifests connected to found catalogs
        for manifest in Manifest.objects.distinct().filter(manifestcatalog__catalog__pk__in=found_catalog_pks):
            self._bump_manifest(manifest, audit_callback)
