import logging
from zentral.core.probes.conf import all_probes
from zentral.contrib.inventory.conf import MACOS, WINDOWS

logger = logging.getLogger('zentral.contrib.osquery.conf')

INVENTORY_QUERY_NAME = "__zentral_inventory_query__"
INVENTORY_DISTRIBUTED_QUERY_PREFIX = "__zentral_distributed_inventory_query_"
INVENTORY_QUERIES = (
    ("os_version",
     "select 'os_version' as table_name, name, major, minor, "
     "patch, build from os_version;"),
    ("system_info",
     "select 'system_info' as table_name, "
     "computer_name, hostname, hardware_model, hardware_serial, "
     "cpu_type, cpu_subtype, cpu_brand, cpu_physical_cores, "
     "cpu_logical_cores, physical_memory from system_info;"),
    ("uptime",
     "select 'uptime' as table_name, total_seconds from uptime;"),
    ("network_interface",
     "select 'network_interface' as table_name, "
     "id.interface, id.mac, "
     "ia.address, ia.mask, ia.broadcast "
     "from interface_details as id, interface_addresses as ia "
     "where ia.interface = id.interface and ia.broadcast > '';"),
)
DEB_PACKAGE_QUERY = "select 'deb_packages' as table_name, * from deb_packages;"
OSX_APP_INSTANCE_QUERY = (
    "select 'apps' as table_name, "
    "bundle_identifier as bundle_id, bundle_name, "
    "bundle_version, bundle_short_version as bundle_version_str, "
    "path as bundle_path "
    "from apps;"
)
MACOS_PRINCIPAL_USER_QUERY = (
    "SELECT 'company_portal' AS table_name,"
    "directory, key, value "
    "FROM ("
    "  SELECT directory"
    "  FROM users"
    "  WHERE directory LIKE '/Users/%'"
    ") u, plist p "
    "WHERE (p.path = u.directory || '/Library/Application Support/com.microsoft.CompanyPortal.usercontext.info');"
)
CERTIFICATES_QUERY = (
    "SELECT 'certificates' AS table_name, * "
    "FROM certificates "
    "WHERE path = '/Library/Keychains/System.keychain' "
    "AND ca = '0' AND ("
    "issuer LIKE '/DC=net/DC=windows/CN=MS-Organization-Access/OU=%' OR "
    "issuer = '/CN=Microsoft Intune MDM Device CA' OR "
    "issuer LIKE '%JSS%'"
    ")"
)
DECORATORS = {
    "load": [
        "SELECT computer_name FROM system_info",
        "SELECT hostname FROM system_info",
        "SELECT hardware_model FROM system_info",
        "SELECT hardware_serial FROM system_info",
        "SELECT uuid AS host_uuid FROM system_info",
        "SELECT name AS os_name FROM os_version"
    ]
}


osquery_query_probes = all_probes.model_filter("OsqueryProbe",
                                               "OsqueryComplianceProbe",
                                               "OsqueryFIMProbe")


def get_inventory_queries_for_machine(machine):
    yield from INVENTORY_QUERIES
    if machine.platform == MACOS:
        yield "apps", OSX_APP_INSTANCE_QUERY
        yield "company_portal", MACOS_PRINCIPAL_USER_QUERY
    if machine.platform in (MACOS, WINDOWS):
        yield "certificates", CERTIFICATES_QUERY
    if machine.has_deb_packages:
        yield "deb_packages", DEB_PACKAGE_QUERY


def get_inventory_query_for_machine(machine):
    return "".join(q for _, q in get_inventory_queries_for_machine(machine))


def get_distributed_inventory_queries(machine, ms):
    if (not ms.os_version
            or (machine.platform == MACOS and not ms.osx_app_instances.count())
            or (machine.has_deb_packages and not ms.deb_packages.count())):
        for table_name, query in get_inventory_queries_for_machine(machine):
            yield "{}{}".format(INVENTORY_DISTRIBUTED_QUERY_PREFIX, table_name), query


def build_osquery_conf(machine, enrollment):
    schedule = {
        INVENTORY_QUERY_NAME: {
            'query': get_inventory_query_for_machine(machine),
            'snapshot': True,
            'interval': 1001
        }
    }
    packs = {}
    file_paths = {}
    file_accesses = []
    # TODO: check performances
    for probe in osquery_query_probes.machine_filtered(machine):
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

    conf = {
        'decorators': DECORATORS,
        'schedule': schedule
    }
    if enrollment:
        conf['options'] = enrollment.configuration.get_dynamic_flags()
    if packs:
        conf['packs'] = packs
    if file_paths:
        conf['file_paths'] = file_paths
    if file_accesses:
        conf['file_accesses'] = list(set(file_accesses))
    return conf
