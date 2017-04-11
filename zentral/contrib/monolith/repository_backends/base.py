from datetime import datetime
import logging
import os.path
import plistlib
from zentral.contrib.monolith.events import post_monolith_repository_updates
from zentral.contrib.monolith.models import Catalog, PkgInfo, PkgInfoCategory, PkgInfoName
from zentral.utils.local_dir import get_and_create_local_dir

logger = logging.getLogger('zentral.contrib.monolith.repository_backends.base')


class BaseRepository(object):
    def serialize_for_event(self):
        return {"module": self.__module__}

    def get_all_catalog_local_path(self):
        return os.path.join(get_and_create_local_dir("monolith", "repository"), "all_catalog.xml")

    def _import_pkg_info_data_catalogs(self, pkg_info_data, event_payloads):
        catalogs = []
        for catalog_name in pkg_info_data.get("catalogs", []):
            catalog_name = catalog_name.strip()
            event_payload = {"catalog": {"name": catalog_name}}
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
        pkg_info_defaults = {"category": pkg_info_category,
                             "data": pkg_info_data,
                             "archived_at": None}
        event_payload = {"pkg_info": {"name": name,
                                      "version": version}}
        try:
            pkg_info = (PkgInfo.objects.prefetch_related("catalogs", "requires", "update_for")
                                       .get(name=pkg_info_name, version=version))
        except PkgInfo.DoesNotExist:
            pkg_info = PkgInfo.objects.create(name=pkg_info_name, version=version,
                                              **pkg_info_defaults)
            pkg_info.catalogs = catalogs
            pkg_info.requires = requires
            pkg_info.update_for = update_for
            event_payload["action"] = "added"
        else:
            for pkg_info_attr, pkg_info_default_val in pkg_info_defaults.items():
                pkg_info_val = getattr(pkg_info, pkg_info_attr)
                if pkg_info_val != pkg_info_default_val:
                    setattr(pkg_info, pkg_info_attr, pkg_info_default_val)
                    event_payload["action"] = "updated"
            for pkg_info_attr, pkg_info_default_val in (("catalogs", catalogs),
                                                        ("requires", requires),
                                                        ("update_for", update_for)):
                pkg_info_val = set(getattr(pkg_info, pkg_info_attr).all())
                if pkg_info_val != set(pkg_info_default_val):
                    setattr(pkg_info, pkg_info_attr, pkg_info_default_val)
                    event_payload["action"] = "updated"
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
        # archived old catalogs
        for c in Catalog.objects.filter(archived_at__isnull=True):
            if c not in found_catalogs:
                c.archived_at = datetime.now()
                c.save()
                event_payloads.append({"catalog": {"name": c.name,
                                                   "id": c.id},
                                       "action": "archived"})
        # archived old pkg_infos
        for pkg_info in PkgInfo.objects.select_related("name").filter(archived_at__isnull=True):
            if pkg_info.get_key() not in found_pkg_infos:
                pkg_info.archived_at = datetime.now()
                pkg_info.save()
                event_payloads.append({"pkg_info": {"name": pkg_info.name.name,
                                                    "version": pkg_info.version},
                                       "action": "archived"})
        post_monolith_repository_updates(self, event_payloads)
