from datetime import datetime
import hashlib
import logging
import plistlib
import uuid
from django.db import transaction
from django.db.models import Count, Q
from zentral.contrib.monolith.models import Catalog, Manifest, PkgInfo, PkgInfoCategory, PkgInfoName
from zentral.core.events.base import AuditEvent, EventRequest
from zentral.core.secret_engines import decrypt, decrypt_str, encrypt_str, rewrap


logger = logging.getLogger('zentral.contrib.monolith.repository_backends.base')


class SyncEventManager:
    def __init__(self, repository, request=None):
        self.repository_pk = repository.pk
        self.event_request = EventRequest.build_from_request(request) if request else None
        self.events = []
        self.event_uuid = uuid.uuid4()
        self.event_index = 0

    def audit_callback(self, instance, action, prev_value=None):
        event = AuditEvent.build(
            instance, action, prev_value=prev_value,
            event_uuid=self.event_uuid, event_index=self.event_index,
            event_request=self.event_request
        )
        event.metadata.add_objects({"monolith_repository": ((self.repository_pk,),)})
        self.events.append(event)
        self.event_index += 1

    def post_events(self):
        for event in self.events:
            event.post()


class BaseRepository:
    kwargs_keys = ()
    encrypted_kwargs_keys = ()
    form_class = None

    def __init__(self, repository, load=True):
        self.repository = repository
        self.name = repository.name
        if load:
            self.load()

    def load(self):
        backend_kwargs = self.get_kwargs()
        for key in self.kwargs_keys:
            setattr(self, key, backend_kwargs.get(key))

    # secrets

    def _get_secret_engine_kwargs(self, subfield):
        if not self.name:
            raise ValueError("Repository must have a name")
        return {"field": f"backend_kwargs.{subfield}",
                "model": "monolith.repository",
                "name": self.name}

    def get_kwargs(self):
        if not isinstance(self.repository.backend_kwargs, dict):
            raise ValueError("Repository hasn't been initialized")
        return {
            k: decrypt_str(v, **self._get_secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in self.repository.backend_kwargs.items()
        }

    def get_kwargs_for_event(self):
        if not isinstance(self.repository.backend_kwargs, dict):
            raise ValueError("Repository hasn't been initialized")
        return {
            k if k not in self.encrypted_kwargs_keys else f"{k}_hash":
            hashlib.sha256(decrypt(v, **self._get_secret_engine_kwargs(k))).hexdigest()
            if k in self.encrypted_kwargs_keys else v
            for k, v in self.repository.backend_kwargs.items()
            if v is not None
        }

    def set_kwargs(self, kwargs):
        self.repository.backend_kwargs = {
            k: encrypt_str(v, **self._get_secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in kwargs.items()
            if v
        }

    def rewrap_kwargs(self):
        self.repository.backend_kwargs = {
            k: rewrap(v, **self._secret_engine_kwargs(k)) if k in self.encrypted_kwargs_keys else v
            for k, v in self.repository.backend_kwargs.items()
        }

    # sync

    def _import_category(self, name, audit_callback):
        pic, created = PkgInfoCategory.objects.get_or_create(repository=self.repository, name=name)
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
        pkg_info_catalogs = pkg_info_data.get("catalogs", [])
        for catalog_name in pkg_info_catalogs:
            catalog_name = catalog_name.strip()
            try:
                catalog = Catalog.objects.get(repository=self.repository, name=catalog_name)
            except Catalog.DoesNotExist:
                catalog = Catalog.objects.create(repository=self.repository, name=catalog_name)
                audit_callback(catalog, AuditEvent.Action.CREATED)
            else:
                if catalog.archived_at:
                    prev_value = catalog.serialize_for_event()
                    catalog.archived_at = None
                    catalog.save()
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
                                       .select_related("repository", "name", "category")
                                       .get(repository=self.repository,
                                            name=pkg_info_name,
                                            version=version))
        except PkgInfo.DoesNotExist:
            pkg_info = PkgInfo.objects.create(repository=self.repository,
                                              name=pkg_info_name,
                                              version=version,
                                              category=pkg_info_category,
                                              data=pkg_info_data)
            pkg_info.catalogs.set(catalogs)
            pkg_info.requires.set(requires)
            pkg_info.update_for.set(update_for)
            audit_callback(pkg_info, AuditEvent.Action.CREATED)
        else:
            updated = False
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
            for pkg_info_attr, pkg_info_values in (
                ("requires", requires),
                ("update_for", update_for),
                ("catalogs", catalogs)
            ):
                pkg_info_old_values = set(getattr(pkg_info, pkg_info_attr).all())
                pkg_info_values = set(pkg_info_values)
                if pkg_info_old_values != pkg_info_values:
                    getattr(pkg_info, pkg_info_attr).set(pkg_info_values)
                    updated = True
            # save updates
            if updated:
                pkg_info.save()  # even if only the m2m attributes were updated, for updated_at
                audit_callback(pkg_info, AuditEvent.Action.UPDATED, prev_value)

        return catalogs, pkg_info

    def _archive_catalog(self, catalog, audit_callback):
        prev_value = catalog.serialize_for_event()
        catalog.archived_at = datetime.utcnow()
        catalog.save()
        audit_callback(catalog, AuditEvent.Action.UPDATED, prev_value)

    def _archive_pkg_info(self, pkg_info, audit_callback):
        prev_value = pkg_info.serialize_for_event()
        pkg_info.archived_at = datetime.utcnow()
        pkg_info.save()
        audit_callback(pkg_info, AuditEvent.Action.UPDATED, prev_value)

    def _bump_manifest(self, manifest, audit_callback):
        prev_value = manifest.serialize_for_event()
        manifest.bump_version()
        audit_callback(manifest, AuditEvent.Action.UPDATED, prev_value)

    def sync_catalogs(self, event_request=None):
        # initialize sync event manager
        sync_event_manager = SyncEventManager(self.repository, event_request)
        audit_callback = sync_event_manager.audit_callback

        found_pkg_info_pks = set([])
        found_catalog_pks = set([])

        # initialize repository icon hashes
        repo_icon_hashes = {}
        icon_hashes_content = self.get_icon_hashes_content()
        if icon_hashes_content:
            icon_hashes = plistlib.loads(icon_hashes_content)
        else:
            icon_hashes = {}
        # update or create current pkg_infos
        for pkg_info_data in plistlib.loads(self.get_all_catalog_content()):
            catalogs, pkg_info = self._import_pkg_info(pkg_info_data, audit_callback)
            found_catalog_pks.update(c.pk for c in catalogs)
            if pkg_info:
                found_pkg_info_pks.add(pkg_info.pk)
                icon_hash = icon_hashes.get(pkg_info.get_original_icon_name())
                if icon_hash:
                    repo_icon_hashes[pkg_info.get_monolith_icon_name()] = icon_hash
        # archive unknown non-local pkg_infos
        for pkg_info in (PkgInfo.objects.prefetch_related("catalogs", "requires", "update_for")
                                        .select_related("category", "name")
                                        .filter(repository=self.repository, archived_at__isnull=True)
                                        .exclude(Q(local=True) | Q(pk__in=found_pkg_info_pks))):
            self._archive_pkg_info(pkg_info, audit_callback)
        # archive old catalogs
        for c in (Catalog.objects.annotate(pkginfo_count=Count("pkginfo",
                                                               filter=Q(pkginfo__archived_at__isnull=True)))
                                 .filter(repository=self.repository, archived_at__isnull=True, pkginfo_count=0)
                                 .exclude(pk__in=found_catalog_pks)):
            self._archive_catalog(c, audit_callback)
        # update repository
        self.repository.icon_hashes = repo_icon_hashes
        self.repository.client_resources = list(self.iter_client_resources())
        self.repository.last_synced_at = datetime.utcnow()
        self.repository.save()
        # bump versions of manifests connected to found catalogs
        for manifest in Manifest.objects.distinct().filter(manifestcatalog__catalog__pk__in=found_catalog_pks):
            self._bump_manifest(manifest, audit_callback)

        # post events
        transaction.on_commit(lambda: sync_event_manager.post_events())

    # to implement in the subclasses

    def get_all_catalog_content(self):
        raise NotImplementedError

    def get_icon_hashes_content(self):
        raise NotImplementedError

    def iter_client_resources(self):
        raise NotImplementedError
