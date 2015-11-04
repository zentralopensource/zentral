from zentral.conf import settings, probes
from zentral.core.exceptions import ImproperlyConfigured

# MachineID: MachineIDSecret$Key$Val
# MachineIDSecret to test if it is a valid request.
# Key / Val to try to link with the machine.
# If no machine found, not a problem.
# MachineID example: TOTO$SERIAL$0123456789

def get_machine_id_secret(settings):
    try:
        return settings['apps']['zentral.contrib.santa']['machine_id_secret']
    except KeyError:
        raise ImproperlyConfigured("Missing attribute 'machine_id_secret' in santa app settings")

machine_id_secret = get_machine_id_secret(settings)


def build_santa_conf(probes):
    rules = []
    for probe_name, probe_d in probes.items():
        santa_l = probe_d.get('santa', None)
        if not santa_l:
            continue
        rules.extend(santa_l)
    return {'rules': rules}

santa_conf = build_santa_conf(probes)
