import logging
from django.db import connection
from django.db.models import Count
from prometheus_client import (CollectorRegistry, Gauge,  # NOQA
                               generate_latest, CONTENT_TYPE_LATEST as prometheus_metrics_content_type)
from zentral.utils.charts import make_dataset
from zentral.utils.json import log_data
from .conf import PLATFORM_CHOICES_DICT, TYPE_CHOICES_DICT
from .events import (post_enrollment_secret_verification_failure, post_enrollment_secret_verification_success,
                     post_inventory_events)
from .exceptions import EnrollmentSecretVerificationFailed
from .models import EnrollmentSecret, MachineSnapshot, MachineSnapshotCommit

logger = logging.getLogger("zentral.contrib.inventory.utils")


def mbu_dashboard_machine_data(mbu):
    # platform
    platform_qs = (MachineSnapshot.objects.filter(currentmachinesnapshot__isnull=False,
                                                  business_unit__meta_business_unit=mbu,
                                                  source=mbu.dashboard_source)
                                          .values("platform").annotate(count=Count("platform")))
    platforms = sorted(((d["platform"], d["count"]) for d in platform_qs),
                       key=lambda t: (-1 * t[1], t[0]))
    yield "platform", "Plaforms", {
        "type": "doughnut",
        "data": {
            "labels": [PLATFORM_CHOICES_DICT.get(p, "Unknown") for p, _ in platforms],
            "datasets": [
                make_dataset([c for _, c in platforms])
            ]
        }
    }
    # type
    type_qs = (MachineSnapshot.objects.filter(currentmachinesnapshot__isnull=False,
                                              business_unit__meta_business_unit=mbu,
                                              source=mbu.dashboard_source)
                                      .values("type").annotate(count=Count("type")))
    types = sorted(((d["type"], d["count"]) for d in type_qs),
                   key=lambda t: (-1 * t[1], t[0]))
    yield "type", "Types", {
        "type": "doughnut",
        "data": {
            "labels": [TYPE_CHOICES_DICT.get(t, "Unknown") for t, _ in types],
            "datasets": [
                make_dataset([c for _, c in types])
            ]
        }
    }
    # os
    query = (
        "select osv.name as name, osv.major as major, osv.minor as minor, osv.patch as patch, "
        "count(*) as count from inventory_osversion as osv "
        "join inventory_machinesnapshot as ms on (osv.id = ms.os_version_id) "
        "join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id) "
        "join inventory_businessunit as bu on (bu.id = ms.business_unit_id) "
        "where bu.meta_business_unit_id = %s and ms.source_id = %s "
        "group by osv.name, osv.major, osv.minor, osv.patch"
    )
    cursor = connection.cursor()
    cursor.execute(query, [mbu.pk, mbu.dashboard_source.pk])
    columns = [col[0] for col in cursor.description]
    os_list = []
    for row in cursor.fetchall():
        os_version = dict(zip(columns, row))
        version_str = ".".join(str(os_version[a]) for a in ("major", "minor", "patch") if os_version.get(a))
        value = "{} {}".format(os_version["name"], version_str).strip()
        os_list.append((value, os_version["count"]))
    os_list.sort(key=lambda t: (-1 * t[1], t[0]))
    yield "os", "OS", {
        "type": "doughnut",
        "data": {
            "labels": [n for n, _ in os_list],
            "datasets": [
                make_dataset([c for _, c in os_list])
            ]
        }
    }


def mbu_dashboard_bundle_data(mbu):
    query = (
        "select a.bundle_id as id, a.bundle_name as name, a.bundle_version_str as version_str, foo.count as count "
        "from ("
        "  select ai.app_id, count(*) as count "
        "  from inventory_osxappinstance as ai "
        "  join inventory_machinesnapshot_osx_app_instances as msai on (msai.osxappinstance_id = ai.id) "
        "  join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msai.machinesnapshot_id) "
        "  join inventory_machinesnapshot as ms on (cms.machine_snapshot_id = ms.id) "
        "  join inventory_businessunit as bu on (ms.business_unit_id = bu.id) "
        "  where bu.meta_business_unit_id = %s and cms.source_id = %s "
        "  group by ai.app_id"
        ") as foo "
        "join inventory_osxapp as a on (foo.app_id = a.id) "
        "where a.bundle_id IN %s"
    )
    cursor = connection.cursor()
    bundle_id_tuple = tuple(mbu.dashboard_osx_app_bundle_id_list)
    cursor.execute(query, [mbu.pk, mbu.dashboard_source.pk, bundle_id_tuple])
    columns = [col[0] for col in cursor.description]
    # group versions and counts by bundle_id
    bundles = {}
    for row in cursor.fetchall():
        bundle = dict(zip(columns, row))
        if bundle["id"] not in bundles:
            bundles[bundle["id"]] = {"name": bundle["name"],
                                     "versions": {}}
        bundles[bundle["id"]]["versions"][bundle["version_str"]] = bundle["count"]
    # build charts config
    for bundle_id in bundle_id_tuple:
        bundle = bundles.get(bundle_id, None)
        if bundle is None:
            continue
        versions = sorted(bundle["versions"].items(), key=lambda t: (-1 * t[1], t[0]), reverse=True)
        config = {
            "type": "doughnut",
            "data": {
                "labels": [v[0] for v in versions],
                "datasets": [
                    make_dataset([v[1] for v in versions])
                ]
            }
        }
        yield bundle_id, bundle["name"], config


def osx_app_count():
    query = """
    select a.bundle_name as name, a.bundle_version_str as version_str,
    s.id as source_id, s.module as source_module, foo.count
    from (
    select ai.app_id, cms.source_id, count(*) as count
    from inventory_osxappinstance as ai
    join inventory_machinesnapshot_osx_app_instances as msai on (msai.osxappinstance_id = ai.id)
    join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = msai.machinesnapshot_id)
    group by ai.app_id, cms.source_id
    ) as foo
    join inventory_osxapp as a on (foo.app_id = a.id)
    join inventory_source as s on (foo.source_id = s.id)
    """
    cursor = connection.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    for row in cursor.fetchall():
        d = dict(zip(columns, row))
        d['source'] = '{}#{}'.format(d.pop('source_module'), d.pop('source_id'))
        for k, v in d.items():
            if k != 'count' and not v:
                d[k] = '_'
        yield d


def os_version_count():
    query = """
    select o.name, o.major, o.minor, o.patch, o.build, s.id as source_id, s.module as source_module,
    count(*) as count
    from inventory_osversion as o
    join inventory_machinesnapshot as ms on (ms.os_version_id = o.id)
    join inventory_currentmachinesnapshot as cms on (cms.machine_snapshot_id = ms.id)
    join inventory_source as s on (cms.source_id = s.id)
    group by o.name, o.major, o.minor, o.patch, o.build, s.id, s.module
    """
    cursor = connection.cursor()
    cursor.execute(query)
    columns = [col[0] for col in cursor.description]
    for row in cursor.fetchall():
        d = dict(zip(columns, row))
        d['source'] = '{}#{}'.format(d.pop('source_module'), d.pop('source_id'))
        for k, v in d.items():
            if k != 'count' and not v:
                d[k] = '_'
        yield d


def get_prometheus_inventory_metrics():
    registry = CollectorRegistry()
    g = Gauge('zentral_inventory_osx_apps', 'Zentral inventory OSX apps',
              ['name', 'version_str', 'source'],
              registry=registry)
    for r in osx_app_count():
        count = r.pop('count')
        g.labels(**r).set(count)
    g = Gauge('zentral_inventory_os_versions', 'Zentral inventory OS Versions',
              ['name', 'major', 'minor', 'patch', 'build', 'source'],
              registry=registry)
    for r in os_version_count():
        count = r.pop('count')
        g.labels(**r).set(count)
    return generate_latest(registry)


def inventory_events_from_machine_snapshot_commit(machine_snapshot_commit):
    source = machine_snapshot_commit.source.serialize()
    diff = machine_snapshot_commit.update_diff()
    if diff is None:
        yield ('inventory_machine_added',
               None,
               {'source': source,
                'machine_snapshot': machine_snapshot_commit.machine_snapshot.serialize()})
        yield ('inventory_heartbeat',
               machine_snapshot_commit.last_seen,
               {'source': source})
        return
    for m2m_attr, event_type in (('links', 'inventory_link_update'),
                                 ('network_interfaces', 'inventory_network_interface_update'),
                                 ('osx_app_instances', 'inventory_osx_app_instance_update'),
                                 ('deb_packages', 'inventory_deb_package_update'),
                                 ('groups', 'inventory_group_update')):
        m2m_diff = diff.get(m2m_attr, {})
        for action in ['added', 'removed']:
            for obj in m2m_diff.get(action, []):
                obj['action'] = action
                if 'source' not in obj:
                    obj['source'] = source
                yield (event_type, None, obj)
    for fk_attr in ('reference',
                    'machine',
                    'business_unit',
                    'os_version',
                    'system_info',
                    'teamviewer',
                    'puppet_node'):
        event_type = 'inventory_{}_update'.format(fk_attr)
        fk_diff = diff.get(fk_attr, {})
        for action in ['added', 'removed']:
            obj = fk_diff.get(action, None)
            if obj:
                if isinstance(obj, dict):
                    event = obj
                    if 'source' not in obj:
                        event['source'] = source
                else:
                    event = {'source': source,
                             fk_attr: obj}
                event['action'] = action
                yield (event_type, None, event)
    added_last_seen = diff.get("last_seen", {}).get("added")
    if added_last_seen:
        yield ("inventory_heartbeat",
               added_last_seen,
               {'source': source})


def commit_machine_snapshot_and_trigger_events(tree):
    try:
        machine_snapshot_commit, machine_snapshot = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    except Exception:
        logger.exception("Could not commit machine snapshot")
        log_data(tree, "/tmp", "snapshot_errors")
    else:
        if machine_snapshot_commit:
            post_inventory_events(machine_snapshot_commit.serial_number,
                                  inventory_events_from_machine_snapshot_commit(machine_snapshot_commit))
        return machine_snapshot


def verify_enrollment_secret(model, secret,
                             user_agent, public_ip_address,
                             serial_number=None, udid=None,
                             meta_business_unit=None,
                             **kwargs):
    try:
        request = EnrollmentSecret.objects.verify(model, secret,
                                                  user_agent, public_ip_address,
                                                  serial_number, udid,
                                                  meta_business_unit,
                                                  **kwargs)
    except EnrollmentSecretVerificationFailed as e:
        post_enrollment_secret_verification_failure(model,
                                                    user_agent, public_ip_address, serial_number,
                                                    e.err_msg, e.enrollment_secret)
        raise
    else:
        post_enrollment_secret_verification_success(request, model)
        return request
