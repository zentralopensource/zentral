from datetime import timedelta
import logging
import time
from django.db import IntegrityError
from django.utils import timezone
from zentral.conf import settings


__all__ = [
    "get_default_snapshot_retention_days",
    "get_cleanup_max_date",
    "cleanup_inventory",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.cleanup")


DELETE_BATCH_SIZE = 1000
MAX_ATTEMPTS = 3


MSC_CUTOFFS_TABLE = "msc_cleanup_cutoffs"

DROP_MSC_CUTOFFS_QUERY = f"DROP TABLE IF EXISTS {MSC_CUTOFFS_TABLE}"

# the cutoffs are computed once and reused by every batch. A snapshot commit
# added while the batches are running only makes the frozen cutoff older than
# the one a fresh aggregate would give, so the newest commit of a machine is
# still never deleted.
CREATE_MSC_CUTOFFS_QUERY = f"""
CREATE TEMPORARY TABLE {MSC_CUTOFFS_TABLE} AS
SELECT serial_number, source_id,
       LEAST(MAX(created_at), timestamp with time zone %s) AS max_created_at
FROM inventory_machinesnapshotcommit
GROUP BY serial_number, source_id
"""

INDEX_MSC_CUTOFFS_QUERY = f"CREATE INDEX ON {MSC_CUTOFFS_TABLE} (serial_number, source_id)"

ANALYZE_MSC_CUTOFFS_QUERY = f"ANALYZE {MSC_CUTOFFS_TABLE}"

# the batches go from the highest id down. A commit is always more recent than its parent,
# so deleting the children first spares the ON DELETE SET NULL updates that the parents
# would otherwise trigger on rows deleted by a later batch anyway.
DELETE_MACHINE_SNAPSHOT_COMMIT_QUERY = f"""
WITH batch AS (
    SELECT msc.id
    FROM inventory_machinesnapshotcommit msc
    JOIN {MSC_CUTOFFS_TABLE} cutoffs
      ON msc.serial_number = cutoffs.serial_number
     AND msc.source_id = cutoffs.source_id
    WHERE msc.id < %s
      AND msc.created_at < cutoffs.max_created_at
    ORDER BY msc.id DESC
    LIMIT %s
)
DELETE FROM inventory_machinesnapshotcommit
WHERE id IN (SELECT id FROM batch)
RETURNING id
"""


ORPHANS = (
    # MachineSnapshot of archived machines
    ("inventory_machinesnapshot", "id",
     (("machine_snapshot_id", "inventory_machinesnapshotcommit"),)),
    # PuppetNode
    ("inventory_puppetnode", "id",
     (("puppet_node_id", "inventory_machinesnapshot"),)),
    # PrincipalUser
    ("inventory_principaluser", "id",
     (("principal_user_id", "inventory_machinesnapshot"),)),
    # SystemInfo
    ("inventory_systeminfo", "id",
     (("system_info_id", "inventory_machinesnapshot"),)),
    # TeamViewer
    ("inventory_teamviewer", "id",
     (("teamviewer_id", "inventory_machinesnapshot"),)),
    # OSVersion
    ("inventory_osversion", "id",
     (("os_version_id", "inventory_machinesnapshot"),)),
    # AndroidApp
    ("inventory_androidapp", "id",
     (("androidapp_id", "inventory_machinesnapshot_android_apps"),)),
    # DebPackage
    ("inventory_debpackage", "id",
     (("debpackage_id", "inventory_machinesnapshot_deb_packages"),)),
    # IOSApp
    ("inventory_iosapp", "id",
     (("iosapp_id", "inventory_machinesnapshot_ios_apps"),)),
    # ProgramInstance
    ("inventory_programinstance", "id",
     (("programinstance_id", "inventory_machinesnapshot_program_instances"),)),
    # Program
    ("inventory_program", "id",
     (("program_id", "inventory_programinstance"),)),
    # MachineGroup
    ("inventory_machinegroup", "id",
     (("machinegroup_id", "inventory_machinesnapshot_groups"),)),
    # Link
    ("inventory_link", "id",
     (("link_id", "inventory_machinesnapshot_links"),
      ("link_id", "inventory_machinegroup_links"),
      ("link_id", "inventory_machinegroup_machine_links"),
      ("link_id", "inventory_businessunit_links"))),
    # Disks
    ("inventory_disk", "id",
     (("disk_id", "inventory_machinesnapshot_disks"),)),
    # NetworkInterface
    ("inventory_networkinterface", "id",
     (("networkinterface_id", "inventory_machinesnapshot_network_interfaces"),)),
    # OSXAppInstance
    ("inventory_osxappinstance", "id",
     (("osxappinstance_id", "inventory_machinesnapshot_osx_app_instances"),)),
    # OSXApp
    ("inventory_osxapp", "id",
     (("app_id", "inventory_osxappinstance"),
      ("bundle_id", "inventory_file"))),
    # ProfilePayload for profiles not linked to machine snapshots
    ("inventory_profile_payloads", "profile_id",
     (("profile_id", "inventory_machinesnapshot_profiles"),)),
    # Payload not linked to profiles
    ("inventory_payload", "id",
     (("payload_id", "inventory_profile_payloads"),)),
    # Profile not linked to machine snapshots
    ("inventory_profile", "id",
     (("profile_id", "inventory_machinesnapshot_profiles"),)),
    # Certificate
    ("inventory_certificate", "id",
     (("signed_by_id", "inventory_osxappinstance"),
      ("signed_by_id", "inventory_certificate"),
      ("signed_by_id", "inventory_file"),
      ("signed_by_id", "inventory_profile"),
      ("certificate_id", "inventory_machinesnapshot_certificates"))),
    # EC2
    ("inventory_ec2instancemetadata", "id",
     (("ec2_instance_metadata_id", "inventory_machinesnapshot"),)),
    ("inventory_ec2instancetag", "id",
     (("ec2instancetag_id", "inventory_machinesnapshot_ec2_instance_tags"),)),
)


def get_default_snapshot_retention_days():
    default_snapshot_retention_days = 30  # 30 days if absent
    try:
        default_snapshot_retention_days = int(
            settings['apps']['zentral.contrib.inventory']['snapshot_retention_days']
        )
    except KeyError:
        pass
    except (TypeError, ValueError):
        logger.error("Wrong value set snapshot_retention_days, default of %s used",
                     default_snapshot_retention_days)
    return max(1, default_snapshot_retention_days)  # minimum 1 day


def get_cleanup_max_date(days=None):
    if days is None:
        days = get_default_snapshot_retention_days()
    else:
        days = max(1, days)  # minimum 1 day
    return timezone.now() - timedelta(days=days)


def build_orphans_query(table, attr, links):
    wheres = []
    for idx, (fk_attr, fk_table) in enumerate(links):
        # we use an alias for the fk_table to avoid collision with the table
        # inventory_certificate references inventory_certificate for example
        wheres.append(
            f"NOT EXISTS (SELECT 1 FROM {fk_table} fkt{idx} WHERE {table}.{attr} = fkt{idx}.{fk_attr})"
        )
    wheres = " AND ".join(wheres)
    return (
        f"WITH batch AS ("
        f" SELECT id FROM {table} WHERE id > %s AND {wheres} ORDER BY id LIMIT %s"
        f") DELETE FROM {table} WHERE id IN (SELECT id FROM batch) RETURNING id"
    )


def run_batched_delete(cursor, query, batch_size, descending=False):
    rowcount = attempts = 0
    # bigger than any id, whatever the width of the column
    last_id = 2 ** 63 - 1 if descending else 0
    next_id = min if descending else max
    while True:
        batch = None
        for attempt in range(MAX_ATTEMPTS):
            if attempt:
                time.sleep(attempt)
            try:
                cursor.execute(query, [last_id, batch_size])
            except IntegrityError:
                # rows can be linked again while we are deleting
                logger.warning("Integrity error on delete batch, attempt %s/%s", attempt + 1, MAX_ATTEMPTS)
            else:
                batch = cursor.fetchall()
                break
        attempts = max(attempts, attempt + 1)
        if batch is None:
            return rowcount, attempts, False
        rowcount += len(batch)
        if len(batch) < batch_size:
            return rowcount, attempts, True
        # the deleted rows are not returned in any particular order
        last_id = next_id(row[0] for row in batch)


def cleanup_table(cursor, result_callback, key, query, batch_size, descending=False):
    start_t = time.time()
    rowcount, attempts, ok = run_batched_delete(cursor, query, batch_size, descending)
    if not ok:
        logger.error("Could not purge table %s because of an integrity error", key)
    result_callback(key, {"attempts": attempts,
                          "rowcount": rowcount,
                          "duration": time.time() - start_t,
                          "status": 0 if ok else 1})


def cleanup_inventory(cursor, result_callback, max_date, batch_size=DELETE_BATCH_SIZE):
    start_t = time.time()

    # delete older machine snapshot commits
    cursor.execute(DROP_MSC_CUTOFFS_QUERY)
    cursor.execute(CREATE_MSC_CUTOFFS_QUERY, [max_date])
    cursor.execute(INDEX_MSC_CUTOFFS_QUERY)
    cursor.execute(ANALYZE_MSC_CUTOFFS_QUERY)
    try:
        cleanup_table(cursor, result_callback, "machine_snapshot_commit",
                      DELETE_MACHINE_SNAPSHOT_COMMIT_QUERY, batch_size, descending=True)
    finally:
        cursor.execute(DROP_MSC_CUTOFFS_QUERY)

    # orphans
    for table, attr, links in ORPHANS:
        cleanup_table(cursor, result_callback, table, build_orphans_query(table, attr, links), batch_size)

    return time.time() - start_t
