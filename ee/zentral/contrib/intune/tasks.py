import logging
import time

from celery import shared_task
from django.db import transaction

from zentral.contrib.inventory.models import CurrentMachineSnapshot
from zentral.contrib.inventory.utils import \
    commit_machine_snapshot_and_trigger_events

from .api_client import Client
from .models import Tenant

logger = logging.getLogger("zentral.contrib.intune.tasks")


def do_sync_inventory(client):
    seen_machines = []
    inventory_source = None
    machines_synced = 0
    machines_removed = 0
    error = None
    start_t = time.time()
    try:
        for ms_tree in client.iter_machine_snapshot_trees():
            seen_machines.append(ms_tree["serial_number"])
            ms = None
            with transaction.atomic():
                ms = commit_machine_snapshot_and_trigger_events(ms_tree)
            if inventory_source is None and ms:
                inventory_source = ms.source
            machines_synced += 1
        if seen_machines and inventory_source:
            with transaction.atomic():
                machines_removed, _ = (
                    CurrentMachineSnapshot.objects.filter(source=inventory_source)
                                                  .exclude(serial_number__in=seen_machines)
                                                  .delete()
                )
    except Exception as e:
        logger.exception("MS Intune Inventory sync error")
        error = str(e)
    result = {
        "status": "SUCCESS" if error is None else "FAILURE",
        "machines_synced": machines_synced,
        "machines_removed": machines_removed,
        "duration": int(time.time() - start_t),
    }
    if error:
        result["error"] = error
    return result


@shared_task
def sync_inventory(tenant_id):
    tenant = Tenant.objects.get(tenant_id=tenant_id)
    client = Client.from_instance(tenant)
    return do_sync_inventory(client)
