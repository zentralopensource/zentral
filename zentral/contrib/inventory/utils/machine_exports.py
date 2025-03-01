from datetime import datetime
import json
import logging
import os
import tempfile
import zipfile
from django.core.files.storage import default_storage
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, transaction
from django.utils.text import slugify

__all__ = [
    "export_machine_snapshots",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.machine_exports")


def export_machine_snapshots(source_name=None, window_size=5000):
    args = []
    query = (
        "select "
        "ms.serial_number, ms.imei, ms.meid, ms.platform, ms.type, ms.extra_facts,"
        "ms.mt_created_at as last_change, max(msc.last_seen) as last_seen,"
        "json_build_object('module', s.module, 'name', s.name) as source,"
        "json_agg(json_build_object("
        "  'anchor_text', l.anchor_text,"
        "  'url', l.url"
        ")) as links,"
        "json_build_object("
        "  'name', o.name,"
        "  'major', o.major,"
        "  'minor', o.minor,"
        "  'patch', o.patch,"
        "  'build', o.build"
        ") as os_version,"
        "json_build_object("
        "  'computer_name', si.computer_name,"
        "  'hostname', si.hostname,"
        "  'hardware_model', si.hardware_model,"
        "  'hardware_serial', si.hardware_serial,"
        "  'cpu_type', si.cpu_type,"
        "  'cpu_subtype', si.cpu_subtype,"
        "  'cpu_brand', si.cpu_brand,"
        "  'cpu_physical_cores', si.cpu_physical_cores,"
        "  'cpu_logical_cores', si.cpu_logical_cores,"
        "  'physical_memory', si.physical_memory"
        ") as system_info,"
        "json_build_object("
        "  'source', json_build_object('type', pus.type, 'properties', pus.properties),"
        "  'unique_id', pu.unique_id,"
        "  'principal_name', pu.principal_name,"
        "  'display_name', pu.display_name"
        ") as principal_user,"
        "json_agg(json_build_object('name', d.name, 'size', d.size)) as disks,"
        "json_agg(json_build_object("
        "  'interface', ni.interface,"
        "  'mac', ni.mac,"
        "  'address', ni.address,"
        "  'mask', ni.mask,"
        "  'broadcast', ni.broadcast"
        ")) as network_interfaces "
        "from inventory_machinesnapshot as ms "
        "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id) "
        "join inventory_machinesnapshotcommit as msc on (msc.machine_snapshot_id = ms.id) "
        "join inventory_source as s on (ms.source_id = s.id) "
        "left join inventory_machinesnapshot_links as ml on (ml.machinesnapshot_id = ms.id) "
        "left join inventory_link as l on (ml.link_id = l.id) "
        "left join inventory_osversion as o on (ms.os_version_id = o.id) "
        "left join inventory_systeminfo as si on (ms.system_info_id = si.id) "
        "left join inventory_principaluser as pu on (ms.principal_user_id = pu.id) "
        "left join inventory_principalusersource as pus on (pu.source_id = pus.id) "
        "left join inventory_machinesnapshot_disks as md on (md.machinesnapshot_id = ms.id) "
        "left join inventory_disk as d on (d.id = md.disk_id) "
        "left join inventory_machinesnapshot_network_interfaces as mni on (mni.machinesnapshot_id = ms.id) "
        "left join inventory_networkinterface as ni on (ni.id = mni.networkinterface_id) "
    )
    if source_name:
        query += "where UPPER(s.name) = %s "
        args.append(source_name.upper())
    query += (
        "group by "
        "ms.serial_number, ms.imei, ms.meid, ms.platform, ms.type, ms.extra_facts, ms.mt_created_at,"
        "s.module, s.name,"
        "o.name, o.major, o.minor, o.patch, o.build,"
        "si.computer_name, si.hostname, si.hardware_model, si.hardware_serial,"
        "si.cpu_type, si.cpu_subtype, si.cpu_brand, si.cpu_physical_cores, si.cpu_logical_cores, si.physical_memory,"
        "pus.type, pus.properties, pu.unique_id, pu.principal_name, pu.display_name "
        "order by s.name, ms.serial_number"
    )

    columns = None
    json_files = []
    current_source_name = json_f = json_p = None

    def _prepare_machine_snapshot(row_d):
        for k, v in list(row_d.items()):
            if v is None:
                del row_d[k]
            elif k == "extra_facts":
                row_d[k] = json.loads(v)
            elif isinstance(v, dict):
                _prepare_machine_snapshot(v)
                if not v:
                    del row_d[k]
            elif isinstance(v, list):
                nv = []
                for vv in v:
                    if isinstance(vv, dict):
                        _prepare_machine_snapshot(vv)
                        if not vv or vv in nv:
                            continue
                    nv.append(vv)
                if nv:
                    row_d[k] = nv
                else:
                    del row_d[k]
        return row_d

    # iter all rows over a server-side cursor
    with transaction.atomic(), connection.chunked_cursor() as cursor:
        cursor.itersize = window_size
        cursor.execute(query, args)
        for row in cursor:
            if columns is None:
                columns = [c.name for c in cursor.description]
            row_d = dict(zip(columns, row))
            source_name = row_d["source"]["name"]
            if source_name != current_source_name:
                if current_source_name:
                    json_f.close()
                    json_files.append((current_source_name, json_p))
                current_source_name = source_name
                json_fh, json_p = tempfile.mkstemp()
                json_f = os.fdopen(json_fh, mode='w')
            json_f.write(json.dumps(_prepare_machine_snapshot(row_d), cls=DjangoJSONEncoder))
            json_f.write("\n")
        if current_source_name:
            json_f.close()
            json_files.append((current_source_name, json_p))

    zip_fh, zip_p = tempfile.mkstemp()
    with zipfile.ZipFile(zip_p, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_a:
        for source_name, json_p in json_files:
            zip_a.write(json_p, "{}.jsonl".format(slugify(source_name)))
            os.unlink(json_p)

    filename = "machine_snapshots-{:%Y-%m-%d_%H-%M-%S}.zip".format(datetime.utcnow())
    filepath = os.path.join("exports", filename)
    with os.fdopen(zip_fh, "rb") as zip_f:
        default_storage.save(filepath, zip_f)
    os.unlink(zip_p)

    return {
        "filepath": filepath,
        "headers": {
            "Content-Type": "application/zip",
            "Content-Length": default_storage.size(filepath),
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    }
