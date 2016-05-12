from zentral.conf import probes as all_probes, machine_probes
from zentral.core.probes.utils import test_probe_event_type
from zentral.core.exceptions import ImproperlyConfigured

DEFAULT_ZENTRAL_INVENTORY_QUERY = "__default_zentral_inventory_query__"


def setup_osquery_probes(all_probes):
    probes = []  # probes with an osquery section
    event_type_probes = []  # probes without an osquery section but with a match on the event type
    for probe_name, probe_d in all_probes.items():
        osquery_d = probe_d.get('osquery', None)
        if not osquery_d:
            if test_probe_event_type(probe_d, 'osquery'):
                event_type_probes.append((probe_name, probe_d))
            continue
        # check and fix existing metadata_filters
        metadata_filters = probe_d.get('filters', {}).get('metadata', None)
        if not metadata_filters:
            probe_d.setdefault('filters', {})['metadata'] = [{'type': 'osquery_result'}]
        else:
            for metadata_filter in metadata_filters:
                if metadata_filter.setdefault('type', "osquery_result") != "osquery_result":
                    # problem
                    ImproperlyConfigured("Osquery probe %s with wrong type metadata_filter %s" %
                                         (probe_d.get('name', '?'), metadata_filter['type']))
        probes.append((probe_name, probe_d))
    return probes, event_type_probes

probes, event_type_probes = setup_osquery_probes(all_probes)


def build_osquery_conf(machine):
    schedule = {DEFAULT_ZENTRAL_INVENTORY_QUERY: {'query': "SELECT 'os_version' as table_name, name, major, minor, "
                                                           "patch, build from os_version;"
                                                           "SELECT 'system_info' as table_name, "
                                                           "computer_name, hostname, hardware_model, hardware_serial, "
                                                           "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
                                                           "cpu_logical_cores, physical_memory from system_info",
                                                  'snapshot': True,
                                                  'interval': 600}}
    file_paths = {}
    probes_to_filter = (probe_d for _, probe_d in probes)
    for probe_d in machine_probes(machine, probes_to_filter=probes_to_filter):
        probe_name = probe_d['name']
        osquery_d = probe_d['osquery']
        for idx, osquery_query in enumerate(osquery_d.get('schedule', [])):
            osquery_query_key = '%s_%d' % (probe_name, idx)
            osquery_query = osquery_query.copy()
            osquery_query.pop('key', None)
            if osquery_query_key in schedule:
                raise ImproperlyConfigured('Query key {} already in schedule'.format(osquery_query_key))
            schedule[osquery_query_key] = osquery_query
        for category, paths in osquery_d.get('file_paths', {}).items():
            if category in file_paths:
                raise ImproperlyConfigured('File path category {} not unique'.format(category))
            file_paths[category] = paths
    osquery_conf = {'schedule': schedule,
                    'file_paths': file_paths}
    return osquery_conf


# django
default_app_config = "zentral.contrib.osquery.apps.ZentralOSQueryAppConfig"
