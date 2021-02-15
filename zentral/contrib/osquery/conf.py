import logging
from zentral.contrib.inventory.conf import MACOS, WINDOWS
from django.db.models import Q


logger = logging.getLogger('zentral.contrib.osquery.conf')


INVENTORY_QUERY_NAME = "ztl-inv"


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
        "SELECT hardware_serial as serial_number FROM system_info",
        "SELECT version FROM osquery_info",
    ]
}


def _get_inventory_queries_for_machine(machine, include_apps=False):
    yield from INVENTORY_QUERIES
    if machine.platform == MACOS:
        if include_apps:
            yield "apps", OSX_APP_INSTANCE_QUERY
        yield "company_portal", MACOS_PRINCIPAL_USER_QUERY
    if machine.platform in (MACOS, WINDOWS):
        yield "certificates", CERTIFICATES_QUERY
    if include_apps and machine.has_deb_packages:
        yield "deb_packages", DEB_PACKAGE_QUERY


def get_inventory_query_for_machine(machine, include_apps):
    return "".join(q for _, q in _get_inventory_queries_for_machine(machine, include_apps))


def build_osquery_conf(machine, enrollment):
    configuration = enrollment.configuration

    conf = {
        'decorators': DECORATORS,
        'options': configuration.serialize_options()
    }

    # inventory
    if configuration.inventory:
        conf.setdefault("schedule", {})[INVENTORY_QUERY_NAME] = {
            'query': get_inventory_query_for_machine(machine, configuration.inventory_apps),
            'interval': configuration.inventory_interval,
            'snapshot': True,
        }

    # File categories
    for file_category in configuration.file_categories.all():
        key = file_category.slug
        if file_category.file_paths:
            conf.setdefault("file_paths", {})[key] = file_category.file_paths
        if file_category.exclude_paths:
            conf.setdefault("exclude_paths", {})[key] = file_category.exclude_paths
        if file_category.file_paths_queries:
            conf.setdefault("file_paths_query", {})[key] = file_category.file_paths_queries
        if file_category.access_monitoring:
            conf.setdefault("file_accesses", []).append(key)

    # ATCs
    for atc in configuration.automatic_table_constructions.all():
        conf.setdefault("auto_table_construction", {})[atc.table_name] = {
            "query": atc.query,
            "path": atc.path,
            "columns": atc.columns,
            "platform": ",".join(atc.platforms) or "all"
        }

    # Packs
    for configuration_pack in (configuration.configurationpack_set
                                            .distinct()
                                            .filter(Q(tags__isnull=True) | Q(tags__in=machine.tags))
                                            .select_related("pack")
                                            .prefetch_related("pack__packquery_set__query")):
        pack = configuration_pack.pack
        conf.setdefault("packs", {})[pack.configuration_key()] = pack.serialize()

    return conf
