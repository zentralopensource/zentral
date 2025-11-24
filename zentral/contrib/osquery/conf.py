import logging
from zentral.contrib.inventory.conf import LINUX, MACOS, WINDOWS
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


EC2_QUERIES = (
    ("ec2_instance_metadata",
     "select 'ec2_instance_metadata' as table_name, * from ec2_instance_metadata;"),
    ("ec2_instance_tags",
     "select 'ec2_instance_tags' as table_name, * from ec2_instance_tags;"),
)


LINUX_DISK_QUERY = (
    "select 'disks' as table_name, "
    "bd.name, bd.block_size * bd.size as size "
    "from block_devices as bd "
    "left join usb_devices as ud on (replace(bd.model, ' ', '_') = ud.model) "
    "where bd.parent = '' and bd.type = '' "
    "and bd.name not like '/dev/dm-%' and bd.name not like '/dev/loop%' and bd.name not like '/dev/md%' "
    "and ud.usb_address is null;"
)


MACOS_DISK_QUERY = (
    "select 'disks' as table_name,"
    "bd.name, bd.block_size * bd.size as size,"
    "m.path, bd.label, de.encryption_status, de.filevault_status "
    "from mounts as m "
    "join block_devices as bd on (bd.name = m.device) "
    "join disk_encryption as de on (m.device = de.name) "
    "where bd.label in ('Macintosh HD', 'Macintosh HD - Data') "
    "or m.path in ('/', '/System/Volumes/Data');"
)


WINDOWS_BUILD_QUERY = (
    "with keys(path) as ("
    "values "
    "('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\CurrentBuild'),"
    "('HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\UBR')"
    ") select 'windows_build' as table_name,"
    "name, data from registry "
    "join keys on (registry.path = keys.path);"
)


WINDOWS_DISK_QUERY = (
    "select 'disks' as table_name, "
    "name, disk_size as size "
    "from disk_info "
    "where type not in ('USB', '1394');"
)


OSX_APP_INSTANCE_QUERY = (
    "select 'apps' as table_name, "
    "bundle_identifier as bundle_id, bundle_name, "
    "bundle_version, bundle_short_version as bundle_version_str, "
    "path as bundle_path "
    "from apps;"
)


WIN_PROGRAM_QUERY = "select 'programs' as table_name, * from programs;"


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
    ");"
)


DECORATORS = {
    "load": [
        "SELECT hardware_serial as serial_number FROM system_info",
        "SELECT version FROM osquery_info",
    ]
}


def _get_inventory_queries_for_machine(machine, include_apps=False, include_ec2=False):
    yield from INVENTORY_QUERIES
    if include_apps:
        if machine.platform == MACOS:
            yield "apps", OSX_APP_INSTANCE_QUERY
        elif machine.platform == WINDOWS:
            yield "programs", WIN_PROGRAM_QUERY
        elif machine.has_deb_packages:
            yield "deb_packages", DEB_PACKAGE_QUERY
    if include_ec2:
        yield from EC2_QUERIES
    if machine.platform == LINUX:
        yield "disks", LINUX_DISK_QUERY
    if machine.platform == MACOS:
        yield "disks", MACOS_DISK_QUERY
        yield "company_portal", MACOS_PRINCIPAL_USER_QUERY
    if machine.platform in (MACOS, WINDOWS):
        yield "certificates", CERTIFICATES_QUERY
    if machine.platform == WINDOWS:
        yield "windows_build", WINDOWS_BUILD_QUERY
        yield "disks", WINDOWS_DISK_QUERY


def get_inventory_query_for_machine(machine, include_apps, include_ec2):
    return "".join(q for _, q in _get_inventory_queries_for_machine(machine, include_apps, include_ec2))


def build_osquery_conf(machine, enrollment):
    configuration = enrollment.configuration

    conf = {
        'decorators': DECORATORS,
        'options': configuration.serialize_options()
    }

    # inventory
    if configuration.inventory:
        conf.setdefault("schedule", {})[INVENTORY_QUERY_NAME] = {
            'query': get_inventory_query_for_machine(
                machine, configuration.inventory_apps, configuration.inventory_ec2
            ),
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
                                            .exclude(excluded_tags__in=machine.tags)
                                            .filter(Q(tags__isnull=True) | Q(tags__in=machine.tags))
                                            .select_related("pack")
                                            .prefetch_related("pack__packquery_set__query__compliance_check",
                                                              "pack__packquery_set__query__tag")):
        pack = configuration_pack.pack
        conf.setdefault("packs", {})[pack.configuration_key()] = pack.serialize()

    return conf
