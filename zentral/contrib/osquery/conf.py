import logging
from zentral.core.probes.conf import ProbeList
from zentral.contrib.inventory.conf import MACOS

logger = logging.getLogger('zentral.contrib.osquery.conf')

DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME = "__default_zentral_inventory_query__"
DEFAULT_ZENTRAL_INVENTORY_QUERY = (
    "select 'os_version' as table_name, name, major, minor, "
    "patch, build from os_version;"
    "select 'system_info' as table_name, "
    "computer_name, hostname, hardware_model, hardware_serial, "
    "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
    "cpu_logical_cores, physical_memory from system_info;"
    "select 'network_interface' as table_name, "
    "id.interface, id.mac, "
    "ia.address, ia.mask, ia.broadcast "
    "from interface_details as id, interface_addresses as ia "
    "where ia.interface = id.interface and ia.broadcast > '';"
)
OSX_APP_INSTANCE_QUERY = (
    "select 'apps' as table_name, "
    "bundle_identifier as bundle_id, bundle_name, "
    "bundle_version, bundle_short_version as bundle_version_str, "
    "path as bundle_path "
    "from apps;"
)
DEB_PACKAGE_QUERY = "select 'deb_packages' as table_name, * from deb_packages;"


def get_inventory_query_for_machine(machine):
    queries = [DEFAULT_ZENTRAL_INVENTORY_QUERY]
    if machine.platform == MACOS:
        queries.append(OSX_APP_INSTANCE_QUERY)
    elif machine.has_deb_packages:
        queries.append(DEB_PACKAGE_QUERY)
    return "".join(queries)


def get_distributed_inventory_query(machine, ms):
    if (not ms.os_version
            or (machine.platform == MACOS and not ms.osx_app_instances.count())
            or (machine.has_deb_packages and not ms.deb_packages.count())):
        return get_inventory_query_for_machine(machine)


def build_osquery_conf(machine):
    schedule = {
        DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME: {
            'query': get_inventory_query_for_machine(machine),
            'snapshot': True,
            'interval': 1001
        }
    }
    packs = {}
    file_paths = {}
    file_accesses = []
    # ProbeList() to avoid cache inconsistency
    # TODO: check performances
    for probe in (ProbeList().model_filter("OsqueryProbe",
                                           "OsqueryComplianceProbe",
                                           "OsqueryFIMProbe")
                             .machine_filtered(machine)):
        # packs or schedule
        if probe.pack_key:
            pack_conf = packs.setdefault(probe.pack_key,
                                         {"discovery": probe.pack_discovery_queries,
                                          "queries": {}})
            query_dict = pack_conf["queries"]
        else:
            query_dict = schedule

        # add probe queries to query_dict
        for osquery_query in probe.iter_scheduled_queries():
            if osquery_query.name in query_dict:
                logger.warning("Query %s skipped, already seen", osquery_query.name)
            else:
                query_dict[osquery_query.name] = osquery_query.to_configuration()

        # file paths / file accesses
        for file_path in getattr(probe, "file_paths", []):
            file_paths[file_path.category] = [file_path.file_path]
            if file_path.file_access:
                file_accesses.append(file_path.category)

    conf = {'schedule': schedule}
    if packs:
        conf['packs'] = packs
    if file_paths:
        conf['file_paths'] = file_paths
    if file_accesses:
        conf['file_accesses'] = list(set(file_accesses))
    return conf
