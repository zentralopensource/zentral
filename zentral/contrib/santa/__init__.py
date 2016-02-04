from zentral.conf import probes as all_probes
from zentral.core.probes.utils import test_probe_event_type
from zentral.core.exceptions import ImproperlyConfigured


def build_santa_conf(all_probes):
    """
    Build the santa conf, the probe lookup dict and the list of santa probes.

    The santa conf is the source of the json document that is sent to the santa
    client when it connects to zentral. It is a list of all the rules found in
    all the configured probes.

    The lookup dict is used when we process a santa event to find the probes
    that, because of the set of santa rules they contain, are responsible for
    its processing. Once we have the probes, we can trigger all the configured
    actions.

    The list of santa probes is a list of (probe_name, probe_d) tupes.
    """
    rules = []
    lookup_d = {}
    probes = []  # probes with a santa section
    event_type_probes = []  # probes without a santa section but with a match on the event type
    for probe_name, probe_d in all_probes.items():
        santa_l = probe_d.get('santa', None)
        if not santa_l:
            if test_probe_event_type(probe_d, "santa"):
                event_type_probes.append((probe_name, probe_d))
            continue
        # check and fix existing metadata_filters
        metadata_filters = probe_d.get('metadata_filters', None)
        if not metadata_filters:
            probe_d['metadata_filters'] = [{'type': 'santa_event'}]
        else:
            for metadata_filter in metadata_filters:
                if metadata_filter.setdefault('type', "santa_event") != "santa_event":
                    # problem
                    ImproperlyConfigured("Santa probe %s with wrong type metadata_filter %s" %
                                         (probe_d.get('name', '?'), metadata_filter['type']))
        probes.append((probe_name, probe_d))
        rules.extend(santa_l)
        for santa_r in santa_l:
            lookup_d.setdefault(santa_r["sha256"], []).append(probe_d.copy())
    probes.sort()
    return {'rules': rules}, lookup_d, probes, event_type_probes

santa_conf, probes_lookup_dict, probes, event_type_probes = build_santa_conf(all_probes)


# django
default_app_config = "zentral.contrib.santa.apps.ZentralSantaAppConfig"
