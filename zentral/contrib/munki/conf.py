from zentral.core.probes.conf import all_probes


event_type_probes = all_probes.module_prefix_filter("munki")
