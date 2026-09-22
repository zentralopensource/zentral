import logging

from celery import shared_task
from django.db import transaction

from zentral.core.events.base import EventRequest

from .apps_books import bulk_assign_location_asset
from .dep import (
    DEP_DEVICE_CREATED,
    DEP_DEVICE_MARKED_DELETED,
    DEP_DEVICE_UNCHANGED,
    DEP_DEVICE_UPDATED,
    DEPClientError,
    assign_dep_virtual_server_default_enrollment,
    define_dep_profile,
    sync_dep_virtual_server_devices,
    try_lock_dep_virtual_server_sync,
)
from .models import DEPEnrollment, DEPVirtualServer, LocationAsset
from .software_updates import sync_software_updates

logger = logging.getLogger("zentral.contrib.mdm.tasks")


# DEP


@shared_task
def sync_dep_virtual_server_devices_task(dep_virtual_server_pk, force_full_sync=False,
                                         serialized_event_request=None, **kwargs):
    # kwargs absorbs task_user, added by the API view for the UserTask created in the celery signal
    event_request = None
    if serialized_event_request:
        event_request = EventRequest.deserialize(serialized_event_request)
    server = DEPVirtualServer.objects.get(pk=dep_virtual_server_pk)
    result = {"dep_virtual_server": {"pk": server.pk,
                                     "name": server.name},
              "operations": {},
              "requested_sync_type": "full_sync" if force_full_sync else "delta_sync",
              "effective_sync_type": "full_sync" if force_full_sync else "delta_sync"}

    def reset_counters():
        result["operations"] = {DEP_DEVICE_CREATED: 0,
                                DEP_DEVICE_UPDATED: 0,
                                DEP_DEVICE_UNCHANGED: 0,
                                DEP_DEVICE_MARKED_DELETED: 0}

    reset_counters()

    with transaction.atomic():
        if not try_lock_dep_virtual_server_sync(server.pk):
            logger.warning("DEP virtual server %s is already being synced", server.pk)
            result["status"] = "SKIPPED"
            return result
        try:
            for _, action in sync_dep_virtual_server_devices(server, force_fetch=force_full_sync,
                                                             event_request=event_request):
                result["operations"][action] += 1
        except DEPClientError as e:
            if e.error_code == "EXPIRED_CURSOR":
                # full sync. It reports on every device, so what the delta walk had counted before
                # it hit the expired cursor would be counted twice.
                result["effective_sync_type"] = "full_sync"
                reset_counters()
                for _, action in sync_dep_virtual_server_devices(server, force_fetch=True,
                                                                 event_request=event_request):
                    result["operations"][action] += 1
            else:
                raise
        if server.default_enrollment_id:
            # the assignment is attributed to whoever asked for the synchronization that scheduled
            # it, so that it shows up in their task list too
            assignment_kwargs = {}
            task_user = kwargs.get("task_user")
            if task_user:
                assignment_kwargs["task_user"] = task_user
            # the devices have to be committed before the assignment task reads them back
            transaction.on_commit(
                lambda: assign_dep_virtual_server_default_enrollment_task.apply_async(
                    (server.pk,), assignment_kwargs
                )
            )

    result["status"] = "SUCCESS"
    return result


@shared_task
def assign_dep_virtual_server_default_enrollment_task(dep_virtual_server_pk, **kwargs):
    server = DEPVirtualServer.objects.select_related("default_enrollment").get(pk=dep_virtual_server_pk)
    result = {"dep_virtual_server": {"pk": server.pk,
                                     "name": server.name},
              "operations": {"assigned": 0, "throttled": 0, "failed": 0, "retry_after_seconds": None}}
    with transaction.atomic():
        if not try_lock_dep_virtual_server_sync(server.pk):
            # the synchronization holding the lock schedules an assignment of its own when it
            # commits, so the work is not lost
            logger.warning("DEP virtual server %s is already being synced", server.pk)
            result["status"] = "SKIPPED"
            return result
        result["operations"] = assign_dep_virtual_server_default_enrollment(server)
    # a throttled device keeps its place in the work list, and the next synchronization finds it
    result["status"] = "THROTTLED" if result["operations"]["throttled"] else "SUCCESS"
    return result


@shared_task
def define_dep_profile_task(dep_enrollment_pk, **kwargs):
    # kwargs absorbs task_user, added by the view for the UserTask created in the celery signal
    dep_enrollment = DEPEnrollment.objects.select_related("virtual_server").get(pk=dep_enrollment_pk)
    return define_dep_profile(dep_enrollment)


# Software updates


@shared_task
def sync_software_updates_task(**kwargs):
    # kwargs absorbs task_user, added by the API view for the UserTask created in the celery signal
    return sync_software_updates()


# Apps & Books


@shared_task
def bulk_assign_location_asset_task(location_asset_pk, dep_virtual_server_pks, **kwargs):
    # kwargs absorbs task_user, added by the view for the UserTask created in the celery signal
    location_asset = LocationAsset.objects.select_related("location", "asset").get(pk=location_asset_pk)
    dep_virtual_servers = DEPVirtualServer.objects.filter(pk__in=dep_virtual_server_pks)
    return {
        "location_asset": location_asset.serialize_for_event(keys_only=True),
        "dep_virtual_servers": [
            dep_virtual_server.serialize_for_event(keys_only=True)
            for dep_virtual_server in dep_virtual_servers
        ],
        "total_assignments": bulk_assign_location_asset(location_asset, dep_virtual_servers),
    }
