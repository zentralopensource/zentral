from zentral.core.probes.conf import ProbeList, all_probes
from .probes import SantaProbe


def iter_santa_policies(probe):
    for santa_p in probe.policies:
        yield (santa_p["sha256"], probe)

probes_lookup_dict = all_probes.class_filter(SantaProbe).dict(iter_santa_policies,
                                                              unique_key=False)


def build_santa_conf(machine):
    """
    Build the santa conf.

    The santa conf is the source of the json document that is sent to the santa
    client when it connects to zentral. It is a list of all the rules found in
    all the configured probes for that client.
    """
    rules = []
    santa_probes = ProbeList().class_filter(SantaProbe)  # ProbeList to avoid cache inconsistency
    for probe in santa_probes.machine_filtered(machine):
        rules.extend(probe.policies)
    return {'rules': rules}
