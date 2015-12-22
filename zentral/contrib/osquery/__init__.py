from zentral.conf import probes as all_probes
from zentral.core.exceptions import ImproperlyConfigured

DEFAULT_ZENTRAL_INVENTORY_QUERY = "__default_zentral_inventory_query__"


def build_osquery_conf(all_probes):
    schedule = {DEFAULT_ZENTRAL_INVENTORY_QUERY: {'query': "SELECT 'os_version' as table_name, * from os_version;"
                                                           "Select 'system_info' as table_name, * from system_info",
                                                  'snapshot': True,
                                                  'interval': 600}}
    file_paths = {}
    probes = []
    for probe_name, probe_d in all_probes.items():
        osquery_d = probe_d.get('osquery', None)
        if not osquery_d:
            continue
        probes.append((probe_name, probe_d))
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
    probes.sort()
    return osquery_conf, probes

osquery_conf, probes = build_osquery_conf(all_probes)


# django
default_app_config = "zentral.contrib.osquery.apps.ZentralOSQueryAppConfig"
