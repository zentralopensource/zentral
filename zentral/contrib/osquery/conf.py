import logging
from zentral.core.probes.conf import ProbeList

logger = logging.getLogger('zentral.contrib.osquery.conf')

DEFAULT_ZENTRAL_INVENTORY_QUERY = "__default_zentral_inventory_query__"


def build_osquery_conf(machine):
    schedule = {
        DEFAULT_ZENTRAL_INVENTORY_QUERY: {
            'query': "SELECT 'os_version' as table_name, name, major, minor, "
                     "patch, build from os_version;"
                     "SELECT 'system_info' as table_name, "
                     "computer_name, hostname, hardware_model, hardware_serial, "
                     "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
                     "cpu_logical_cores, physical_memory from system_info;"
                     "SELECT 'network_interface' as table_name, "
                     "id.interface, id.mac, "
                     "ia.address, ia.mask, ia.broadcast "
                     "from interface_details as id, interface_addresses as ia "
                     "where ia.interface = id.interface and ia.broadcast > '';",
            'snapshot': True,
            'interval': 600
        }
    }
    file_paths = {}
    file_accesses = []
    # ProbeList() to avoid cache inconsistency
    # TODO: check performances
    for probe in (ProbeList().model_filter("OsqueryProbe",
                                           "OsqueryComplianceProbe",
                                           "OsqueryFIMProbe")
                             .machine_filtered(machine)):
        for osquery_query in probe.iter_scheduled_queries():
            if osquery_query.name in schedule:
                logger.warning("Query %s skipped, already in schedule", osquery_query.name)
            else:
                schedule[osquery_query.name] = osquery_query.to_configuration()
        for file_path in getattr(probe, "file_paths", []):
            file_paths[file_path.category] = [file_path.file_path]
            if file_path.file_access:
                file_accesses.append(file_path.category)

    conf = {'schedule': schedule}
    if file_paths:
        conf['file_paths'] = file_paths
    if file_accesses:
        conf['file_accesses'] = list(set(file_accesses))
    return conf
