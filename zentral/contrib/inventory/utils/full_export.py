import hashlib
import json
import logging
import os.path
import secrets
import tempfile
import zipfile
from contextlib import contextmanager

from django.core.files.storage import default_storage
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connections, transaction

from zentral.utils.db import get_read_only_database
from zentral.utils.time import naive_utcnow

__all__ = [
    "FULL_EXPORT_TABLE_NAMES",
    "do_full_export",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.full_export")


# A table holds the rows a current machine snapshot reaches, directly or through the rows of another
# exported table.

CURRENT_MS_IDS = "select machine_snapshot_id from inventory_currentmachinesnapshot"


def ms_fk_ids(column):
    return f"select {column} from inventory_machinesnapshot where id in ({CURRENT_MS_IDS})"


def m2m_ids(through_table, column):
    return f"select {column} from {through_table} where machinesnapshot_id in ({CURRENT_MS_IDS})"


def fk_ids(column, table, ids):
    return f"select {column} from {table} where id in ({ids})"


def rows(table, ids, columns="*"):
    return f"select {columns} from {table} where id in ({ids})"


def link_rows(through_table, columns):
    return (f"select machinesnapshot_id ms_id, {columns} from {through_table} "
            f"where machinesnapshot_id in ({CURRENT_MS_IDS})")


BUSINESS_UNIT_IDS = ms_fk_ids("business_unit_id")
OSX_APP_INSTANCE_IDS = m2m_ids("inventory_machinesnapshot_osx_app_instances", "osxappinstance_id")
PROFILE_IDS = m2m_ids("inventory_machinesnapshot_profiles", "profile_id")
PROGRAM_INSTANCE_IDS = m2m_ids("inventory_machinesnapshot_program_instances", "programinstance_id")

# the certificates of the snapshots, the signers of the app instances and of the profiles, and the chains above them
CERTIFICATE_QUERY = (
    "with recursive reachable_certificate as ("
    "select id, signed_by_id from inventory_certificate where id in ("
    f"{m2m_ids('inventory_machinesnapshot_certificates', 'certificate_id')} "
    f"union {fk_ids('signed_by_id', 'inventory_osxappinstance', OSX_APP_INSTANCE_IDS)} "
    f"union {fk_ids('signed_by_id', 'inventory_profile', PROFILE_IDS)}) "
    "union "
    "select c.id, c.signed_by_id from inventory_certificate c join reachable_certificate r on (c.id = r.signed_by_id)"
    ") "
    "select * from inventory_certificate where id in (select id from reachable_certificate)"
)


FULL_EXPORT_QUERIES = [
    # first the current snapshots
    ("machine",
     "select cms.serial_number, cms.last_seen,"
     "ms.id ms_id, ms.mt_hash, ms.mt_created_at,"
     "ms.business_unit_id, ms.ec2_instance_metadata_id, ms.os_version_id,"
     "ms.principal_user_id, ms.source_id, ms.system_info_id,"
     "ms.reference, ms.public_ip_address, ms.platform, ms.type, ms.imei, ms.meid, ms.extra_facts "
     "from inventory_currentmachinesnapshot cms "
     "join inventory_machinesnapshot ms on (cms.machine_snapshot_id = ms.id)"),
    # meta/business units
    ("business_unit", rows("inventory_businessunit", BUSINESS_UNIT_IDS)),
    ("meta_business_unit",
     rows("inventory_metabusinessunit", fk_ids("meta_business_unit_id", "inventory_businessunit", BUSINESS_UNIT_IDS))),
    # extra many to one tables
    ("os_version", rows("inventory_osversion", ms_fk_ids("os_version_id"))),
    ("principal_user", rows("inventory_principaluser", ms_fk_ids("principal_user_id"))),
    ("source",
     rows("inventory_source",
          f"{ms_fk_ids('source_id')} union {fk_ids('source_id', 'inventory_businessunit', BUSINESS_UNIT_IDS)}",
          columns="id, mt_hash, mt_created_at, module, name")),
    ("system_info", rows("inventory_systeminfo", ms_fk_ids("system_info_id"))),
    # disks
    ("disk", rows("inventory_disk", m2m_ids("inventory_machinesnapshot_disks", "disk_id"))),
    ("machine_disk", link_rows("inventory_machinesnapshot_disks", "disk_id")),
    # network interfaces
    ("network_interface",
     rows("inventory_networkinterface",
          m2m_ids("inventory_machinesnapshot_network_interfaces", "networkinterface_id"))),
    ("machine_network_interface",
     link_rows("inventory_machinesnapshot_network_interfaces", "networkinterface_id network_interface_id")),
    # certificates
    ("certificate", CERTIFICATE_QUERY),
    ("machine_certificate", link_rows("inventory_machinesnapshot_certificates", "certificate_id")),
    # profiles
    ("profile", rows("inventory_profile", PROFILE_IDS)),
    ("machine_profile", link_rows("inventory_machinesnapshot_profiles", "profile_id")),
    # macOS apps
    ("macos_app", rows("inventory_osxapp", fk_ids("app_id", "inventory_osxappinstance", OSX_APP_INSTANCE_IDS))),
    ("macos_app_instance",
     rows("inventory_osxappinstance", OSX_APP_INSTANCE_IDS,
          columns="id, mt_hash, mt_created_at,"
                  "bundle_path, executable_path, path, sha_1, sha_256, type, app_id macos_app_id, signed_by_id,"
                  "team_id, cd_hash, entitlements, signing_time, secure_signing_time")),
    ("machine_macos_app_instance",
     link_rows("inventory_machinesnapshot_osx_app_instances", "osxappinstance_id macos_app_instance_id")),
    # Android apps
    ("android_app", rows("inventory_androidapp", m2m_ids("inventory_machinesnapshot_android_apps", "androidapp_id"))),
    ("machine_android_app", link_rows("inventory_machinesnapshot_android_apps", "androidapp_id android_app_id")),
    # Debian packages
    ("deb_package", rows("inventory_debpackage", m2m_ids("inventory_machinesnapshot_deb_packages", "debpackage_id"))),
    ("machine_deb_package", link_rows("inventory_machinesnapshot_deb_packages", "debpackage_id deb_package_id")),
    # EC2
    ("ec2_instance_metadata", rows("inventory_ec2instancemetadata", ms_fk_ids("ec2_instance_metadata_id"))),
    ("ec2_instance_tag",
     rows("inventory_ec2instancetag", m2m_ids("inventory_machinesnapshot_ec2_instance_tags", "ec2instancetag_id"))),
    ("machine_ec2_instance_tag",
     link_rows("inventory_machinesnapshot_ec2_instance_tags", "ec2instancetag_id ec2_instance_tag_id")),
    # iOS apps
    ("ios_app", rows("inventory_iosapp", m2m_ids("inventory_machinesnapshot_ios_apps", "iosapp_id"))),
    ("machine_ios_app", link_rows("inventory_machinesnapshot_ios_apps", "iosapp_id ios_app_id")),
    # Programs
    ("program", rows("inventory_program", fk_ids("program_id", "inventory_programinstance", PROGRAM_INSTANCE_IDS))),
    ("program_instance", rows("inventory_programinstance", PROGRAM_INSTANCE_IDS)),
    ("machine_program_instance",
     link_rows("inventory_machinesnapshot_program_instances", "programinstance_id program_instance_id")),
    # TODO: compliance checks
    # TODO: blueprints
]


FULL_EXPORT_TABLE_NAMES = [name for name, _ in FULL_EXPORT_QUERIES]


def normalize_tables(tables):
    if tables is None:
        return FULL_EXPORT_TABLE_NAMES
    if not tables:
        raise ValueError("At least one table is required")
    unknown = sorted(set(tables) - set(FULL_EXPORT_TABLE_NAMES))
    if unknown:
        raise ValueError(f"Unknown tables: {', '.join(unknown)}")
    return [name for name in FULL_EXPORT_TABLE_NAMES if name in tables]


@contextmanager
def export_transaction():
    connection = connections[get_read_only_database()]
    # SET TRANSACTION must be the first statement of a transaction. The isolation level can only be raised
    # when the export opens the transaction, not when it runs inside an outer one.
    set_isolation_level = not connection.in_atomic_block
    with transaction.atomic(using=connection.alias):
        if set_isolation_level:
            with connection.cursor() as cursor:
                cursor.execute("set transaction isolation level repeatable read")
        yield connection


def iter_batches(cursor, batch, window_size):
    while batch:
        yield batch
        batch = cursor.fetchmany(window_size)


def iter_tables(tables, window_size):
    with export_transaction() as connection:
        for table, query in FULL_EXPORT_QUERIES:
            if table not in tables:
                continue
            with connection.chunked_cursor() as cursor:
                cursor.execute(query)
                # the description of a server-side cursor is only known after the first fetch
                batch = cursor.fetchmany(window_size)
                columns = [c.name for c in cursor.description]
                yield table, columns, iter_batches(cursor, batch, window_size)


class HashingFile:
    def __init__(self, f):
        self._f = f
        self._hash = hashlib.sha256()
        self.size = 0

    def write(self, data):
        self._f.write(data)
        self._hash.update(data)
        self.size += len(data)

    def close(self):
        self._f.close()

    def hexdigest(self):
        return self._hash.hexdigest()


class JSONLPart:
    def __init__(self, table, index):
        self.name = f"zentral_{table}_{index:04d}.jsonl"
        fh, self.path = tempfile.mkstemp()
        self.file = HashingFile(os.fdopen(fh, mode="wb"))
        self.rows = 0

    def write_row(self, obj):
        self.file.write(json.dumps(obj, cls=DjangoJSONEncoder).encode("utf-8") + b"\n")
        self.rows += 1

    def close(self):
        self.file.close()
        return {"rows": self.rows, "size": self.file.size, "sha256": self.file.hexdigest()}


def iter_jsonl_parts(table, columns, batches, max_temp_file_size):
    part = None
    part_index = 0
    for batch in batches:
        for row in batch:
            if part is None or part.file.size > max_temp_file_size:
                if part:
                    yield part
                part_index += 1
                part = JSONLPart(table, part_index)
            part.write_row(dict(zip(columns, row)))
    if part:
        yield part


def do_full_export(tables=None, max_temp_file_size=2**30, window_size=5000):
    tables = normalize_tables(tables)
    export_dt = naive_utcnow()
    export_id = f"{export_dt:%Y%m%dT%H%M%SZ}-{secrets.token_hex(4)}"
    manifest = {
        "version": 1,
        "export_id": export_id,
        "exported_at": f"{export_dt:%Y-%m-%dT%H:%M:%SZ}",
        "format": "JSONL",
        "tables": {},
        "files": {},
    }

    # create ZIP archive
    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_a:
        for table, columns, batches in iter_tables(tables, window_size):
            table_manifest = {"rows": 0, "columns": [{"name": column} for column in columns], "files": []}
            for part in iter_jsonl_parts(table, columns, batches, max_temp_file_size):
                file_manifest = part.close()
                zip_a.write(part.path, part.name)
                os.unlink(part.path)
                table_manifest["rows"] += file_manifest["rows"]
                table_manifest["files"].append(part.name)
                manifest["files"][part.name] = {"table": table, **file_manifest}
            manifest["tables"][table] = table_manifest
        zip_a.writestr("manifest.json", json.dumps(manifest, indent=2))

    # copy ZIP archive to default storage
    with os.fdopen(zip_fh, "rb") as zip_f:
        filepath = default_storage.save(os.path.join("exports", f"full_inventory_export-{export_id}.zip"), zip_f)
    filename = os.path.basename(filepath)

    # cleanup local ZIP archive
    os.unlink(zip_p)

    # return info for task
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
        "manifest": manifest,
    }
