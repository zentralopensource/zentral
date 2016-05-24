from zentral.core.probes.conf import all_probes
from zentral.core.exceptions import ImproperlyConfigured

DEFAULT_ZENTRAL_INVENTORY_QUERY = "__default_zentral_inventory_query__"


event_type_probes = (all_probes
                     .module_prefix_filter("osquery")
                     .filter(lambda p: "osquery" not in p))

probes = all_probes.filter(lambda p: "osquery" in p)


def iter_osquery_schedule_queries(probe_d):
    probe_name = probe_d['name']
    osquery_d = probe_d['osquery']
    for idx, osquery_query in enumerate(osquery_d.get('schedule', [])):
        yield ('%s_%d' % (probe_name, idx), osquery_query)


def item_func(probe_d):
    for osquery_query_key, osquery_query in iter_osquery_schedule_queries(probe_d):
        yield (osquery_query_key, (probe_d, osquery_query))

queries_lookup_dict = probes.dict(item_func)


def build_osquery_conf(machine):
    schedule = {
        DEFAULT_ZENTRAL_INVENTORY_QUERY: {
            'query': "SELECT 'os_version' as table_name, name, major, minor, "
                     "patch, build from os_version;"
                     "SELECT 'system_info' as table_name, "
                     "computer_name, hostname, hardware_model, hardware_serial, "
                     "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
                     "cpu_logical_cores, physical_memory from system_info",
            'snapshot': True,
            'interval': 600
        }
    }
    file_paths = {}
    for probe_d in probes.machine_filtered(machine):
        for osquery_query_key, osquery_query in iter_osquery_schedule_queries(probe_d):
            osquery_query = osquery_query.copy()
            osquery_query.pop('key', None)
            if osquery_query_key in schedule:
                raise ImproperlyConfigured(
                          'Query key {} already in schedule'.format(osquery_query_key)
                      )
            schedule[osquery_query_key] = osquery_query
        for category, paths in probe_d['osquery'].get('file_paths', {}).items():
            if category in file_paths:
                raise ImproperlyConfigured(
                          'File path category {} not unique'.format(category)
                      )
            file_paths[category] = paths
    osquery_conf = {'schedule': schedule,
                    'file_paths': file_paths}
    return osquery_conf


# django
default_app_config = "zentral.contrib.osquery.apps.ZentralOSQueryAppConfig"
