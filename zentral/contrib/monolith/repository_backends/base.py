from datetime import datetime
import logging
import os.path
import plistlib
from zentral.contrib.monolith.events import post_monolith_repository_updates
from zentral.contrib.monolith.models import Catalog, PkgInfo, PkgInfoCategory, PkgInfoName
from zentral.utils.local_dir import get_and_create_local_dir

logger = logging.getLogger('zentral.contrib.monolith.repository_backends.base')


class BaseRepository(object):
    def __init__(self, config):
        self.manual_catalog_management = config.get("manual_catalog_management", False)
        if self.manual_catalog_management:
            self.default_catalog_name = config.get("default_catalog", "Not assigned").strip()
        else:
            self.default_catalog_name = None

    def serialize_for_event(self):
        return {"module": self.__module__}

    def get_all_catalog_local_path(self):
        return os.path.join(get_and_create_local_dir("monolith", "repository"), "all_catalog.xml")

    def _import_pkg_info_data_catalogs(self, pkg_info_data, event_payloads):
        catalogs = []
        if self.default_catalog_name:
            # force the catalog to the default catalog
            pkg_info_catalogs = [self.default_catalog_name]
        else:
            # take the catalogs from the pkg info data
            pkg_info_catalogs = pkg_info_data.get("catalogs", [])
        for catalog_name in pkg_info_catalogs:
            catalog_name = catalog_name.strip()
            event_payload = {"catalog": {"name": catalog_name},
                             "type": "catalog"}
            try:
                catalog = Catalog.objects.get(name=catalog_name)
            except Catalog.DoesNotExist:
                catalog = Catalog.objects.create(name=catalog_name)
                event_payload["action"] = "added"
            else:
                if catalog.archived_at:
                    catalog.archived_at = None
                    catalog.save()
                    event_payload["action"] = "unarchived"
            catalogs.append(catalog)
            if "action" in event_payload:
                event_payload["catalog"]["id"] = catalog.id
                event_payloads.append(event_payload)
        return catalogs

    def _import_pkg_info_data(self, pkg_info_data, event_payloads):
        name = pkg_info_data['name']
        version = pkg_info_data['version']
        logger.debug('PKGINFO %s %s', name, version)
        # catalogs
        catalogs = self._import_pkg_info_data_catalogs(pkg_info_data, event_payloads)
        if not catalogs:
            logger.warning('PKGINFO %s %s w/o catalogs', name, version)
            return catalogs, None
        # name
        pkg_info_name, _ = PkgInfoName.objects.get_or_create(name=name)
        # category
        pkg_info_category = None
        category = pkg_info_data.get('category', None)
        if category:
            pkg_info_category, pkg_info_category_created = PkgInfoCategory.objects.get_or_create(name=category)
            if pkg_info_category_created:
                event_payloads.append({"category": {"name": pkg_info_category.name,
                                                    "id": pkg_info_category.id},
                                       "type": "category",
                                       "action": "added"})
        # requires
        requires = [pif for pif, created in (PkgInfoName.objects.get_or_create(name=n)
                                             for n in pkg_info_data.get('requires', []))]
        # update_for
        update_for = [pif for pif, created in (PkgInfoName.objects.get_or_create(name=n)
                                               for n in pkg_info_data.get('update_for', []))]
        # serialize pkg_info_data
        for key, val in pkg_info_data.items():
            if isinstance(val, datetime):
                pkg_info_data[key] = val.isoformat()
        # save PkgInfo in db
        event_payload = {"pkg_info": {"name": name,
                                      "version": version},
                         "type": "pkg_info"}
        try:
            pkg_info = (PkgInfo.objects.prefetch_related("catalogs", "requires", "update_for")
                                       .get(name=pkg_info_name, version=version))
        except PkgInfo.DoesNotExist:
            pkg_info = PkgInfo.objects.create(name=pkg_info_name,
                                              version=version,
                                              category=pkg_info_category,
                                              data=pkg_info_data)
            pkg_info.catalogs.set(catalogs)
            pkg_info.requires.set(requires)
            pkg_info.update_for.set(update_for)
            event_payload["action"] = "added"
        else:
            # if the pkg exists, but is archived, consider it like a new pkg
            if pkg_info.archived_at:
                diff = None
                pkg_info.archived_at = None
                event_payload["action"] = "added"
            else:
                diff = {}

            # update category if necessary
            pkg_info_old_category = pkg_info.category
            if pkg_info_old_category != pkg_info_category:
                pkg_info.category = pkg_info_category
                if diff is not None:
                    attr_diff = {}
                    if pkg_info_old_category:
                        attr_diff["removed"] = str(pkg_info_old_category)
                    if pkg_info_category:
                        attr_diff["added"] = str(pkg_info_category)
                    diff["category"] = attr_diff
                    event_payload["action"] = "updated"

            # update data if necessary
            pkg_info_old_data = pkg_info.data
            if pkg_info_old_data != pkg_info_data:
                pkg_info.data = pkg_info_data
                if diff is not None:
                    attr_diff = {}
                    if pkg_info_old_data:
                        attr_diff["removed"] = pkg_info_old_data
                    if pkg_info_data:
                        attr_diff["added"] = pkg_info_data
                    diff["data"] = attr_diff
                    event_payload["action"] = "updated"

            # save updates
            if event_payload.get("action"):
                pkg_info.save()

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
                    if diff is not None:
                        attr_diff = {}
                        removed = pkg_info_old_values - pkg_info_values
                        if removed:
                            attr_diff = {"removed": sorted(str(r) for r in removed)}
                        added = pkg_info_values - pkg_info_old_values
                        if added:
                            attr_diff = {"added": sorted(str(a) for a in added)}
                        diff[pkg_info_attr] = attr_diff
                        event_payload["action"] = "updated"

            # include the updates in the event payload
            if diff:
                event_payload["pkg_info"]["diff"] = diff

        if "action" in event_payload:
            event_payloads.append(event_payload)

        return catalogs, pkg_info.get_key()

    def sync_catalogs(self):
        with open(self.download_all_catalog(), "rb") as f:
            catalog_plist = plistlib.load(f)
        found_pkg_infos = set([])
        found_catalogs = set([])
        event_payloads = []
        # update or create current pkg_infos
        for pkg_info_data in catalog_plist:
            catalogs, pkg_info_key = self._import_pkg_info_data(pkg_info_data, event_payloads)
            found_catalogs.update(catalogs)
            if pkg_info_key:
                if pkg_info_key in found_pkg_infos:
                    logger.warning('PKGINFO %s %s already found', pkg_info_key[0], pkg_info_key[1])
                else:
                    found_pkg_infos.update([pkg_info_key])
        # archive old catalogs if auto catalog management
        if not self.manual_catalog_management:
            for c in Catalog.objects.filter(archived_at__isnull=True):
                if c not in found_catalogs:
                    c.archived_at = datetime.now()
                    c.save()
                    event_payloads.append({"catalog": {"name": c.name,
                                                       "id": c.id},
                                           "type": "catalog",
                                           "action": "archived"})
        # archive old pkg_infos
        for pkg_info in PkgInfo.objects.select_related("name").filter(archived_at__isnull=True):
            if pkg_info.get_key() not in found_pkg_infos:
                pkg_info.archived_at = datetime.now()
                pkg_info.save()
                event_payloads.append({"pkg_info": {"name": pkg_info.name.name,
                                                    "version": pkg_info.version},
                                       "type": "pkg_info",
                                       "action": "archived"})
        post_monolith_repository_updates(self, event_payloads)
