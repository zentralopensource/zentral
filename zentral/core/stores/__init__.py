from importlib import import_module
import logging
from zentral.conf import settings

logger = logging.getLogger('zentral.core.stores')

__all__ = ['stores']


def get_store_class(module_path):
    class_name = "EventStore"
    module = import_module(module_path)
    return getattr(module, class_name)


def get_stores(settings):
    stores = []
    for store_name, store_conf in settings['stores'].items():
        store_conf = store_conf.copy()
        store_conf['store_name'] = store_name
        store_class = get_store_class(store_conf.pop('backend'))
        stores.append(store_class(store_conf))
    return stores


def get_frontend_store(stores):
    fe_store = None
    for store in stores:
        if store.frontend:
            if fe_store:
                logger.error('Multiple frontend store')
            else:
                fe_store = store
    if not fe_store:
        logger.error('No frontend store')
        try:
            fe_store = stores[0]
        except IndexError:
            logger.error('No stores')
    return fe_store


stores = get_stores(settings)
frontend_store = get_frontend_store(stores)
