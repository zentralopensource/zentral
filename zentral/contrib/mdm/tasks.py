import logging

from celery import shared_task

from .apps_books import bulk_assign_location_asset
from .dep import DEPClientError, SyncCounters, define_dep_profile, sync_dep_virtual_server_devices
from .models import DEPEnrollment, DEPVirtualServer, LocationAsset
from .software_updates import sync_software_updates

logger = logging.getLogger("zentral.contrib.mdm.tasks")


# DEP


@shared_task
def sync_dep_virtual_server_devices_task(dep_virtual_server_pk, force_full_sync=False,
                                         serialized_event_request=None, **kwargs):
    # kwargs absorbs task_user, added by the API view for the UserTask created in the celery signal
    server = DEPVirtualServer.objects.get(pk=dep_virtual_server_pk)
    result = {"dep_virtual_server": {"pk": server.pk,
                                     "name": server.name},
              "requested_sync_type": "full_sync" if force_full_sync else "delta_sync",
              "effective_sync_type": "full_sync" if force_full_sync else "delta_sync"}

    def run(force_fetch):
        return SyncCounters(sync_dep_virtual_server_devices(
            server, force_fetch=force_fetch, serialized_event_request=serialized_event_request
        )).run()

    try:
        result["operations"] = run(force_full_sync)
    except DEPClientError as e:
        if e.error_code == "EXPIRED_CURSOR":
            # full sync, from scratch: whatever the delta sync had counted is not part of it
            result["effective_sync_type"] = "full_sync"
            result["operations"] = run(True)
        else:
            raise

    return result


@shared_task
def define_dep_profile_task(dep_enrollment_pk):
    dep_enrollment = DEPEnrollment.objects.select_related("virtual_server").get(pk=dep_enrollment_pk)
    return define_dep_profile(dep_enrollment)


# Software updates


@shared_task
def sync_software_updates_task():
    return sync_software_updates()


# Apps & Books


@shared_task
def bulk_assign_location_asset_task(location_asset_pk, dep_virtual_server_pks):
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
