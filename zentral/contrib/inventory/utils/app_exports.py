import csv
from datetime import datetime
import logging
import os
import tempfile
import zipfile
from django.core.files.storage import default_storage
from django.db import connection, transaction
from django.utils.text import slugify


__all__ = [
    "export_machine_android_apps",
    "export_machine_deb_packages",
    "export_machine_ios_apps",
    "export_machine_macos_app_instances",
    "export_machine_program_instances",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.app_exports")


def _export_machine_csv_zip(query, source_name, basename, window_size=5000):
    columns = None
    csv_files = []
    current_source_name = csv_f = csv_w = csv_p = None

    # iter all rows over a server-side cursor
    query_args = []
    if source_name:
        query_args.append(source_name.upper())
    with transaction.atomic(), connection.chunked_cursor() as cursor:
        cursor.itersize = window_size
        cursor.execute(query, query_args)
        for row in cursor:
            if columns is None:
                columns = [c.name for c in cursor.description]
            source_name = row[columns.index("source_name")]
            if source_name != current_source_name:
                if current_source_name:
                    csv_f.close()
                    csv_files.append((current_source_name, csv_p))
                current_source_name = source_name
                csv_fh, csv_p = tempfile.mkstemp()
                csv_f = os.fdopen(csv_fh, mode="w", newline="")
                csv_w = csv.writer(csv_f)
                csv_w.writerow(columns)
            csv_w.writerow(row)
        if current_source_name:
            csv_f.close()
            csv_files.append((current_source_name, csv_p))

    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_a:
        for source_name, csv_p in csv_files:
            zip_a.write(csv_p, "{}.csv".format(slugify(source_name)))
            os.unlink(csv_p)

    filename = "{}-{:%Y-%m-%d_%H-%M-%S}.zip".format(slugify(basename).replace("-", "_"), datetime.utcnow())
    filepath = os.path.join("exports", filename)
    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)
    os.unlink(zip_p)

    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Length": default_storage.size(filepath),
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    }


def export_machine_android_apps(source_name=None):
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name, cms.last_seen,"
        "aa.display_name, aa.version_name, aa.version_code, aa.package_name, aa.installer_package_name "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_android_apps as msaa on (msaa.machinesnapshot_id = ms.id) "
        "join inventory_androidapp as aa on (aa.id = msaa.androidapp_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
    query += "order by s.name, cms.serial_number, aa.display_name, aa.version_name, aa.id;"
    return _export_machine_csv_zip(query, source_name, "inventory_machine_android_apps_export")


def export_machine_deb_packages(source_name=None):
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name, cms.last_seen,"
        "dp.name, dp.version, dp.source, dp.size, dp.arch,"
        "dp.revision, dp.status, dp.maintainer, dp.section, dp.priority "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_deb_packages as msdp on (msdp.machinesnapshot_id = ms.id) "
        "join inventory_debpackage as dp on (dp.id = msdp.debpackage_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
    query += "order by s.name, cms.serial_number, dp.name, dp.version, dp.revision, dp.id;"
    return _export_machine_csv_zip(query, source_name, "inventory_machine_deb_packages_export")


def export_machine_ios_apps(source_name=None):
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name, cms.last_seen,"
        "ia.name, ia.version, ia.ad_hoc_signed, ia.app_store_vendable, ia.beta_app,"
        "ia.bundle_size, ia.device_based_vpp, ia.identifier, ia.is_validated, ia.short_version "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_ios_apps as msia on (msia.machinesnapshot_id = ms.id) "
        "join inventory_iosapp as ia on (ia.id = msia.iosapp_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
    query += "order by s.name, cms.serial_number, ia.name, ia.version, ia.id;"
    return _export_machine_csv_zip(query, source_name, "inventory_machine_ios_apps_export")


def export_machine_macos_app_instances(source_name=None):
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name, cms.last_seen,"
        "oa.bundle_id, oa.bundle_name, oa.bundle_display_name, oa.bundle_version, oa.bundle_version_str,"
        "oai.bundle_path, oai.path "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_osx_app_instances as msoai on (msoai.machinesnapshot_id = ms.id) "
        "join inventory_osxappinstance as oai on (oai.id = msoai.osxappinstance_id) "
        "join inventory_osxapp as oa on (oa.id = oai.app_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
    query += (
        "order by s.name, cms.serial_number, oa.bundle_id, oa.bundle_name, oa.bundle_version, oa.bundle_version_str;"
    )
    return _export_machine_csv_zip(query, source_name, "inventory_machine_macos_app_instances_export")


def export_machine_program_instances(source_name=None):
    query = (
        "select cms.serial_number, s.module as source_module, s.name as source_name, cms.last_seen,"
        "p.name, p.version, p.language, p.publisher, p.identifying_number,"
        "pi.install_location, pi.install_source, pi.uninstall_string, pi.install_date "
        "from inventory_currentmachinesnapshot as cms "
        "join inventory_machinesnapshot as ms on ms.id = cms.machine_snapshot_id "
        "join inventory_source as s on ms.source_id = s.id "
        "join inventory_machinesnapshot_program_instances as mspi on (mspi.machinesnapshot_id = ms.id) "
        "join inventory_programinstance as pi on (pi.id = mspi.programinstance_id) "
        "join inventory_program as p on (p.id = pi.program_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
    query += "order by s.name, cms.serial_number, p.name, p.version, p.identifying_number, p.id;"
    return _export_machine_csv_zip(query, source_name, "inventory_machine_program_instances_export")
