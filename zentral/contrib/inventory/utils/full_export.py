from datetime import datetime
import json
import logging
import os.path
import tempfile
import zipfile
from django.core.files.storage import default_storage
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connections, transaction
from zentral.utils.db import get_read_only_database


__all__ = [
    "do_full_export"
]


logger = logging.getLogger("zentral.contrib.inventory.utils.full_export")


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
    ("business_unit", "select * from inventory_businessunit"),
    ("meta_business_unit", "select * from inventory_metabusinessunit"),
    # extra many to one tables
    ("os_version", "select * from inventory_osversion"),
    ("principal_user", "select * from inventory_principaluser"),
    ("source", "select id, mt_hash, mt_created_at, module, name from inventory_source"),
    ("system_info", "select * from inventory_systeminfo"),
    # disks
    ("disk", "select * from inventory_disk"),
    ("machine_disks",
     "select machinesnapshot_id ms_id, disk_id "
     "from inventory_machinesnapshot_disks"),
    # network interfaces
    ("network_interface", "select * from inventory_networkinterface"),
    ("machine_network_interface",
     "select machinesnapshot_id ms_id, networkinterface_id network_interface_id "
     "from inventory_machinesnapshot_network_interfaces"),
    # certificates
    ("certificate", "select * from inventory_certificate"),
    ("machine_certificate",
     "select machinesnapshot_id ms_id, certificate_id "
     "from inventory_machinesnapshot_certificates"),
    # profiles
    ("profile", "select * from inventory_profile"),
    ("machine_profile",
     "select machinesnapshot_id ms_id, profile_id "
     "from inventory_machinesnapshot_profiles"),
    # macOS apps
    ("macos_app", "select * from inventory_osxapp"),
    ("macos_app_instance",
     "select id, mt_hash, mt_created_at,"
     "bundle_path, path, sha_1, sha_256, type, app_id macos_app_id, signed_by_id "
     "from inventory_osxappinstance"),
    ("machine_macos_app_instance",
     "select machinesnapshot_id ms_id, osxappinstance_id macos_app_instance_id "
     "from inventory_machinesnapshot_osx_app_instances"),
    # Android apps
    ("android_app", "select * from inventory_androidapp"),
    ("machine_android_app",
     "select machinesnapshot_id ms_id, androidapp_id android_app_id "
     "from inventory_machinesnapshot_android_apps"),
    # Debian packages
    ("deb_package", "select * from inventory_debpackage"),
    ("machine_deb_package",
     "select machinesnapshot_id ms_id, debpackage_id deb_package_id "
     "from inventory_machinesnapshot_deb_packages"),
    # EC2
    ("ec2_instance_metadata", "select * from inventory_ec2instancemetadata"),
    ("ec2_instance_tag", "select * from inventory_ec2instancetag"),
    ("machine_ec2_instance_tag",
     "select machinesnapshot_id ms_id, ec2instancetag_id ec2_instance_tag_id "
     "from inventory_machinesnapshot_ec2_instance_tags"),
    # iOS apps
    ("ios_app", "select * from inventory_iosapp"),
    ("machine_ios_app",
     "select machinesnapshot_id ms_id, iosapp_id ios_app_id "
     "from inventory_machinesnapshot_ios_apps"),
    # Programs
    ("program", "select * from inventory_program"),
    ("program_instance", "select * from inventory_programinstance"),
    ("machine_program_instance",
     "select machinesnapshot_id ms_id, programinstance_id program_instance_id "
     "from inventory_machinesnapshot_program_instances"),
    # TODO: compliance checks
    # TODO: blueprints
]


def iter_model_exports(export_dt, max_temp_file_size, window_size):
    # for each model
    # - execute the query
    # - write the results in a temporary file
    database = get_read_only_database()
    for model_name, query in FULL_EXPORT_QUERIES:
        model_export_f = model_export_p = None
        file_index = 0
        with transaction.atomic(), connections[database].chunked_cursor() as cursor:
            cursor.itersize = window_size
            cursor.execute(query, [export_dt])
            columns = None
            for row in cursor:
                if columns is None:
                    columns = [c.name for c in cursor.description]
                if model_export_f is None or model_export_f.tell() > max_temp_file_size:
                    if model_export_f:
                        model_export_f.close()
                        yield model_name, file_index, model_export_p
                    file_index += 1
                    model_export_fh, model_export_p = tempfile.mkstemp()
                    model_export_f = os.fdopen(model_export_fh, mode="w", newline="")
                obj = dict(zip(columns, row))
                json.dump(obj, model_export_f, cls=DjangoJSONEncoder)
                model_export_f.write("\n")
        if model_export_f:
            model_export_f.close()
            yield model_name, file_index, model_export_p


def do_full_export(max_temp_file_size=2**30, window_size=5000):
    export_dt = datetime.utcnow()

    # create ZIP archive
    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode="w", compression=zipfile.ZIP_DEFLATED) as zip_a:
        for model_name, file_index, file_p in iter_model_exports(
            export_dt, max_temp_file_size, window_size
        ):
            zip_a.write(file_p, f"zentral_{model_name}_{file_index:04d}.jsonl")
            os.unlink(file_p)

    # copy ZIP archive to default storage
    filename = f"full_inventory_export-{export_dt:%Y-%m-%d_%H-%M-%S}.zip"
    filepath = os.path.join("exports", filename)
    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)

    # cleanup local ZIP archive
    os.unlink(zip_p)

    # return info for task
    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    }
