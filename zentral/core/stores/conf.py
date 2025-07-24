import logging
import os
import threading
import weakref
from base.notifier import notifier
from zentral.conf import settings
from .models import Store


logger = logging.getLogger('zentral.core.stores.conf')


__all__ = ['stores']


class Stores:
    default_max_custom_store_count = 3

    def __init__(self, with_sync=False):
        self._stores = None
        self._admin_console_store = None
        self._lock = threading.Lock()
        self.with_sync = with_sync
        self._sync_started = False

    def clear(self, *args, **kwargs):
        with self._lock:
            self._stores = None
            self._admin_console_store = None

    def _start_sync(self):
        if self.with_sync:
            if not self._sync_started:
                notifier.add_callback("stores.store", weakref.WeakMethod(self.clear))
                self._sync_started = True

    def _load(self, force=False):
        self._start_sync()
        if self._stores is None or force:
            self._stores = []
            self._admin_console_store = None
            first_store = None
            # IMPORTANT order_by created_at to get a stable ordering, even if the stores are renamed
            for db_store in Store.objects.prefetch_related("events_url_authorized_roles").all().order_by("created_at"):
                store = db_store.get_backend(load=True)
                self._stores.append(store)
                # admin console store?
                if db_store.admin_console:
                    if self._admin_console_store:
                        logger.error('Multiple admin console store')
                    else:
                        self._admin_console_store = store
                elif not first_store:
                    first_store = store
            if not self._admin_console_store:
                logger.error('No admin console store')
                if first_store:
                    self._admin_console_store = first_store
                else:
                    logger.error('No stores')

    # public API

    @property
    def max_custom_store_count(self):
        try:
            return int(settings["apps"]["zentral.core.stores"]["max_custom_store_count"])
        except KeyError:
            pass
        except (TypeError, ValueError):
            logger.error("max_custom_store_count must be an integer")
        return self.default_max_custom_store_count

    @property
    def admin_console_store(self):
        with self._lock:
            self._load()
            return self._admin_console_store

    def __iter__(self):
        with self._lock:
            self._load()
            yield from self._stores

    def iter_events_url_store_for_user(self, key, user):
        for store in self:
            if not getattr(store, f"{key}_events_url", False):
                # store doesn't implement this functionality
                continue
            if not user.is_superuser and store.events_url_authorized_role_pk_set:
                if not user.group_pk_set:
                    # user is not a member of any group, it cannot be a match
                    continue
                if not store.events_url_authorized_role_pk_set.intersection(user.group_pk_set):
                    # no common groups
                    continue
            yield store

    def iter_queue_worker_stores(self):
        for store in self:
            if not store.read_only:
                yield store


# used for the tests
zentral_stores_sync = os.environ.get("ZENTRAL_STORES_SYNC", "1") == "1"


stores = Stores(with_sync=zentral_stores_sync)
