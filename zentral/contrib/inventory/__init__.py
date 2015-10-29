from importlib import import_module
from zentral.conf import settings

__all__ = ['inventory']


def get_inventory(settings):
    inventory_settings = settings['apps']['zentral.contrib.inventory'].copy()
    backend = inventory_settings.pop('backend')
    module = import_module(backend)
    return getattr(module, "InventoryClient")(inventory_settings)

inventory = get_inventory(settings)
