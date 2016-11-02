from zentral.core.probes.conf import ProbeList


def build_santa_conf(machine):
    """
    Build the santa conf.

    The santa conf is the source of the json document that is sent to the santa
    client when it connects to zentral. It is a list of all the rules found in
    all the configured probes for that client.
    """
    rules = []
    for probe in (ProbeList().model_filter("SantaProbe")  # ProbeList to avoid cache inconsistency
                             .machine_filtered(machine)):
        # TODO test duplicated rules
        rules.extend(r.to_configuration() for r in probe.rules)
    return {'rules': rules}
