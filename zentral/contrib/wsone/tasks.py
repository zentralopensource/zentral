import logging
import time
from celery import shared_task
from django.db import transaction
from zentral.contrib.inventory.models import CurrentMachineSnapshot
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from .api_client import Client
from .events import post_sync_started_event, post_sync_finished_event
from .models import Instance


logger = logging.getLogger("zentral.contrib.wsone.tasks")


def do_sync_inventory(instance, client, serialized_event_request=None):
    post_sync_started_event(instance, serialized_event_request)
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
        logger.exception("Workspace ONE instance sync error")
        error = str(e)
    result = {
        "status": "SUCCESS" if error is None else "FAILURE",
        "machines_synced": machines_synced,
        "machines_removed": machines_removed,
        "duration": int(time.time() - start_t),
    }
    if error:
        result["error"] = error
    post_sync_finished_event(instance, serialized_event_request, result, client.latest_rate_limit)
    return result


@shared_task
def sync_inventory(instance_pk, serialized_event_request):
    instance = Instance.objects.get(pk=instance_pk)
    client = Client.from_instance(instance)
    return do_sync_inventory(instance, client, serialized_event_request)
