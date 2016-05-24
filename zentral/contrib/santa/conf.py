from zentral.core.probes.conf import all_probes


event_type_probes = (all_probes
                     .module_prefix_filter("santa")
                     .filter(lambda p: "santa" not in p))

probes = all_probes.filter(lambda p: "santa" in p)


def iter_santa_rules(probe_d):
    for santa_r in probe_d.get("santa", []):
        yield (santa_r["sha256"], probe_d)

probes_lookup_dict = probes.dict(iter_santa_rules, unique_key=False)


def build_santa_conf(machine):
    """
    Build the santa conf.

    The santa conf is the source of the json document that is sent to the santa
    client when it connects to zentral. It is a list of all the rules found in
    all the configured probes for that client.
    """
    rules = []
    for probe_d in probes.machine_probes(machine):
        santa_l = probe_d['santa']
        rules.extend(santa_l)
    return {'rules': rules}


# django
default_app_config = "zentral.contrib.santa.apps.ZentralSantaAppConfig"
