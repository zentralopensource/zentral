from importlib import import_module
from zentral.conf import settings


def get_exporters(settings):
    inventory_settings = settings['apps']['zentral.contrib.inventory']
    for inv_exp_settings in inventory_settings.get('exporters', []):
        module = import_module(inv_exp_settings['backend'])
        yield getattr(module, "InventoryExporter")(inv_exp_settings)


exporters = list(get_exporters(settings))
