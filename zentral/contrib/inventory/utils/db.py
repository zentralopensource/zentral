import logging
from zentral.utils.json import save_dead_letter
from zentral.contrib.inventory.compliance_checks import jmespath_checks_cache
from zentral.contrib.inventory.events import (iter_inventory_events)
from zentral.contrib.inventory.models import MachineSnapshotCommit


__all__ = [
    "commit_machine_snapshot_and_trigger_events",
    "commit_machine_snapshot_and_yield_events",
]


logger = logging.getLogger("zentral.contrib.inventory.snapshots.db")


def inventory_events_from_machine_snapshot_commit(machine_snapshot_commit):
    source = machine_snapshot_commit.source.serialize()
    diff = machine_snapshot_commit.update_diff()
    if diff is None:
        machine_payload = machine_snapshot_commit.machine_snapshot.serialize()
        machine_payload
        yield ('add_machine',
               None,
               machine_snapshot_commit.machine_snapshot.serialize(
                   exclude=["deb_packages",
                            "disks",
                            "network_interfaces",
                            "osx_app_instances",
                            "program_instances"]
               ))
        yield ('inventory_heartbeat',
               machine_snapshot_commit.last_seen,
               {'source': source})
        return
    for m2m_diff_attr in ('android_apps',
                          'certificates',
                          'deb_packages',
                          'disks',
                          'groups',
                          'ios_apps',
                          'links',
                          'network_interfaces',
                          'osx_app_instances',
                          'program_instances',
                          'profiles',
                          'ec2_instance_tags'):
        m2m_diff = diff.get(m2m_diff_attr, {})
        if not m2m_diff:
            continue
        event_attr = m2m_diff_attr[:-1]
        for diff_action, event_action in [('added', 'add'), ('removed', 'remove')]:
            event_type = f"{event_action}_machine_{event_attr}"
            for obj in m2m_diff.get(diff_action, []):
                yield (event_type, None, {event_attr: obj, "source": source})
    for attr in ('business_unit',
                 'os_version',
                 'system_info',
                 'teamviewer',
                 'puppet_node',
                 'principal_user',
                 'extra_facts',
                 'ec2_instance_metadata'):
        fk_diff = diff.get(attr, {})
        if not fk_diff:
            continue
        for diff_action, event_action in [('added', 'add'), ('removed', 'remove')]:
            event_type = f"{event_action}_machine_{attr}"
            obj = fk_diff.get(diff_action)
            if obj:
                if not isinstance(obj, dict):
                    # this should not happen
                    logger.error("Unsupported diff value %s %s", attr, diff_action)
                    continue
                yield (event_type, None, {attr: obj, "source": source})
    added_last_seen = diff.get("last_seen", {}).get("added")
    if added_last_seen:
        yield ("inventory_heartbeat", added_last_seen, {'source': source})


def commit_machine_snapshot_and_trigger_events(tree):
    try:
        msc, machine_snapshot, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    except Exception:
        logger.exception("Could not commit machine snapshot")
        save_dead_letter(tree, "machine snapshot commit error")
    else:
        # inventory events
        if msc:
            for event in iter_inventory_events(msc.serial_number, inventory_events_from_machine_snapshot_commit(msc)):
                event.post()
        # compliance checks
        for event in jmespath_checks_cache.process_tree(tree, last_seen):
            event.post()
        return machine_snapshot


def commit_machine_snapshot_and_yield_events(tree):
    try:
        msc, _, last_seen = MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    except Exception:
        logger.exception("Could not commit machine snapshot")
    else:
        # inventory events
        if msc:
            yield from iter_inventory_events(msc.serial_number, inventory_events_from_machine_snapshot_commit(msc))
        # compliance checks
        yield from jmespath_checks_cache.process_tree(tree, last_seen)
