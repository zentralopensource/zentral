from zentral.conf import settings, probes
from zentral.core.exceptions import ImproperlyConfigured

__all__ = ['machine_id_secret', 'santa_conf', 'probes_lookup_dict']

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


def build_santa_conf_and_lookup_dict(probes):
    """
    Build the santa conf and the probe lookup dict.

    The santa conf is the source of the json document that is sent to the santa
    client when it connects to zentral. It is a list of all the rules found in
    all the configured probes.

    The lookup dict is used when we process a santa event to find the probes
    that, because of the set of santa rules they contain, are responsible for
    its processing. Once we have the probes, we can trigger all the configured
    actions.
    """
    rules = []
    lookup_d = {}
    for probe_name, probe_d in probes.items():
        santa_l = probe_d.get('santa', None)
        if not santa_l:
            continue
        rules.extend(santa_l)
        for santa_r in santa_l:
            lookup_d.setdefault(santa_r["sha256"], []).append(probe_d.copy())
    return {'rules': rules}, lookup_d

santa_conf, probes_lookup_dict = build_santa_conf_and_lookup_dict(probes)
