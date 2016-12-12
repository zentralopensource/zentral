from importlib import import_module
from zentral.conf import settings
from .base import InventoryError  # NOQA


def get_clients(settings):
    inventory_settings = settings['apps']['zentral.contrib.inventory']
    for inv_cli_settings in inventory_settings.get('clients', []):
        module = import_module(inv_cli_settings['backend'])
        yield getattr(module, "InventoryClient")(inv_cli_settings)


clients = list(get_clients(settings))
