from zentral.conf import settings, probes
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


def build_osquery_conf(probes):
    schedule = {}
    file_paths = {}
    for probe_name, probe_d in probes.items():
        osquery_d = probe_d.get('osquery', None)
        if not osquery_d:
            continue
        for idx, osquery_query in enumerate(osquery_d.get('schedule', [])):
            osquery_query_key = '%s_%d' % (probe_name, idx)
            osquery_query = osquery_query.copy()
            osquery_query.pop('key', None)
            schedule[osquery_query_key] = osquery_query
        for category, paths in osquery_d.get('file_paths', {}).items():
            if category in file_paths:
                raise ImproperlyConfigured('File path category %s not unique', category)
            file_paths[category] = paths
    return {'schedule': schedule,
            'file_paths': file_paths}

osquery_conf = build_osquery_conf(probes)
