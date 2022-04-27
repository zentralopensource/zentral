from datetime import timedelta
import logging
import time
from django.db import IntegrityError
from django.utils import timezone
from zentral.conf import settings

logger = logging.getLogger("zentral.contrib.inventory.cleanup")


DELETE_MACHINE_SNAPSHOT_COMMIT_QUERY = """
DELETE FROM inventory_machinesnapshotcommit AS msc
USING (
    SELECT serial_number, source_id,
           LEAST(MAX(created_at), timestamp with time zone %s) as max_created_at
    FROM inventory_machinesnapshotcommit
    GROUP BY serial_number, source_id
) AS msc_agg
WHERE
    msc.serial_number = msc_agg.serial_number
    AND msc.source_id = msc_agg.source_id
    AND msc.created_at < msc_agg.max_created_at;
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
    # Certificate
    ("inventory_certificate", "id",
     (("signed_by_id", "inventory_osxappinstance"),
      ("signed_by_id", "inventory_certificate"),
      ("signed_by_id", "inventory_file"),
      ("certificate_id", "inventory_machinesnapshot_certificates"))),
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


def get_min_date(days=None):
    if days is None:
        days = get_default_snapshot_retention_days()
    else:
        days = max(1, days)  # minimum 1 day
    return timezone.now() - timedelta(days=days)


def cleanup_inventory(cursor, result_callback, min_date):
    # delete older machine snapshot commits
    start_t = time.time()
    cursor.execute(DELETE_MACHINE_SNAPSHOT_COMMIT_QUERY, [min_date])
    result_callback("machine_snapshot_commit", {"rowcount": cursor.rowcount,
                                                "duration": time.time() - start_t,
                                                "status": 0})

    # orphans
    for table, attr, links in ORPHANS:
        wheres = []
        for idx, (fk_attr, fk_table) in enumerate(links):
            # we use an alias for the fk_table to avoid collision with the table
            # inventory_certificate references inventory_certificate for example
            wheres.append(
                f"NOT EXISTS (SELECT 1 FROM {fk_table} fkt{idx} WHERE {table}.{attr} = fkt{idx}.{fk_attr})"
            )
        wheres = " AND ".join(wheres)
        query = f"DELETE FROM {table} WHERE {wheres}"

        # 3 attempts. Things could be added in the linked table while we are deleting.
        # TODO: better?
        for i in range(3):
            if i:
                print(f"Retry in {i}s…")
                time.sleep(i)
            orphan_start_t = time.time()
            try:
                cursor.execute(query)
            except IntegrityError:
                print(f"Could not purge table {table} because of an integrity error")
            else:
                result_callback(table, {"attempts": i + 1,
                                        "rowcount": cursor.rowcount,
                                        "duration": time.time() - orphan_start_t,
                                        "status": 0})
                break
        else:
            result_callback(table, {"attempts": i + 1,
                                    "status": 1})
    return time.time() - start_t
