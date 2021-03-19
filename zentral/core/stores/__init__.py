from importlib import import_module
import logging
from django.utils.functional import SimpleLazyObject
from zentral.conf import settings

logger = logging.getLogger('zentral.core.stores')


__all__ = ['frontend_store', 'stores']


class Stores:
    @staticmethod
    def _get_store_class(module_path):
        class_name = "EventStore"
        module = import_module(module_path)
        return getattr(module, class_name)

    def __init__(self, settings):
        self.frontend_store = None
        self.stores = {}
        for store_name, store_conf in settings['stores'].items():
            store_conf = store_conf.copy()
            store_conf['store_name'] = store_name
            store_class = self._get_store_class(store_conf.pop('backend'))
            store = store_class(store_conf)
            self.stores[store_name] = store
            if store.frontend:
                if self.frontend_store:
                    logger.error('Multiple frontend store')
                else:
                    self.frontend_store = store
            if not self.frontend_store:
                logger.error('No frontend store')
                if self.stores:
                    self.frontend_store = self.stores[0]
                else:
                    logger.error('No stores')

    def __iter__(self):
        yield from self.stores.values()

    def _iter_events_url_store_for_user(self, key, user):
        for store in self.stores.values():
            if not getattr(store, f"{key}_events_url", False):
                # store doesn't implement this functionality
                continue
            if not user.is_superuser and store.events_url_authorized_groups:
                if not user.group_name_set:
                    # use is not a member of any group, it cannot be a match
                    continue
                if not store.events_url_authorized_groups.intersection(user.group_name_set):
                    # no common groups
                    continue
            yield store

    def iter_machine_events_url_store_for_user(self, user):
        yield from self._iter_events_url_store_for_user("machine", user)

    def iter_probe_events_url_store_for_user(self, user):
        yield from self._iter_events_url_store_for_user("probe", user)


stores = SimpleLazyObject(lambda: Stores(settings))
frontend_store = SimpleLazyObject(lambda: stores.frontend_store)
