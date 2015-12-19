from zentral.conf import settings, probes as all_probes
from zentral.core.exceptions import ImproperlyConfigured

# Enroll_secret structure : EnrollSecretSecret$Key$Val
# EnrollSecretSecret to test if it is a good request.
# Key / Val to try to link with the machine.
# If no machine found, not a problem.
# Enroll_secret example : BLABLA$SERIAL$AZLKJZAENEAZLKJ13098


def get_enroll_secret_secret(settings):
    try:
        return settings['apps']['zentral.contrib.osquery']['enroll_secret_secret']
    except KeyError:
        raise ImproperlyConfigured("Missing attribute 'enroll_secret_secret' in osquery app settings")

enroll_secret_secret = get_enroll_secret_secret(settings)

# The osquery conf for the connected daemons.


def build_osquery_conf(all_probes):
    schedule = {}
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
            schedule[osquery_query_key] = osquery_query
        for category, paths in osquery_d.get('file_paths', {}).items():
            if category in file_paths:
                raise ImproperlyConfigured('File path category %s not unique', category)
            file_paths[category] = paths
    osquery_conf = {'schedule': schedule,
                    'file_paths': file_paths}
    probes.sort()
    return osquery_conf, probes

osquery_conf, probes = build_osquery_conf(all_probes)


# django
default_app_config = "zentral.contrib.osquery.apps.ZentralOSQueryAppConfig"
