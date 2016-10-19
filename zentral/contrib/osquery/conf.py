from zentral.core.probes.conf import ProbeList, all_probes
from zentral.core.exceptions import ImproperlyConfigured
from .probes import OSQueryProbe

DEFAULT_ZENTRAL_INVENTORY_QUERY = "__default_zentral_inventory_query__"


def item_func(probe):
    for osquery_query_key, osquery_query in probe.iter_schedule_queries():
        yield (osquery_query_key, (probe, osquery_query))

queries_lookup_dict = all_probes.class_filter(OSQueryProbe).dict(item_func)


def build_osquery_conf(machine):
    schedule = {
        DEFAULT_ZENTRAL_INVENTORY_QUERY: {
            'query': "SELECT 'os_version' as table_name, name, major, minor, "
                     "patch, build from os_version;"
                     "SELECT 'system_info' as table_name, "
                     "computer_name, hostname, hardware_model, hardware_serial, "
                     "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
                     "cpu_logical_cores, physical_memory from system_info;"
                     "SELECT 'network_interface' as table_name, "
                     "id.interface, id.mac, "
                     "ia.address, ia.mask, ia.broadcast "
                     "from interface_details as id, interface_addresses as ia "
                     "where ia.interface = id.interface and ia.broadcast > '';",
            'snapshot': True,
            'interval': 600
        }
    }
    file_paths = {}
    osquery_probes = ProbeList().class_filter(OSQueryProbe)  # ProbeList to avoid cache inconsistency
    for probe in osquery_probes.machine_filtered(machine):
        for osquery_query_key, osquery_query in probe.iter_schedule_queries():
            osquery_query = osquery_query.copy()
            osquery_query.pop('key', None)
            if osquery_query_key in schedule:
                raise ImproperlyConfigured(
                          'Query key {} already in schedule'.format(osquery_query_key)
                      )
            schedule[osquery_query_key] = osquery_query
        for category, paths in probe.file_paths.items():
            if category in file_paths:
                raise ImproperlyConfigured(
                          'File path category {} not unique'.format(category)
                      )
            file_paths[category] = paths
    return {'schedule': schedule,
            'file_paths': file_paths}
