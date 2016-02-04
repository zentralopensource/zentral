from zentral.conf import probes as all_probes
from zentral.core.probes.utils import test_probe_event_type


def build_inventory_conf(all_probes):
    event_type_probes = []  # probes with a match on the event type
    for probe_name, probe_d in all_probes.items():
        if test_probe_event_type(probe_d, 'inventory'):
            event_type_probes.append((probe_name, probe_d))
    return event_type_probes

event_type_probes = build_inventory_conf(all_probes)

# django
default_app_config = "zentral.contrib.inventory.apps.ZentralInventoryAppConfig"
