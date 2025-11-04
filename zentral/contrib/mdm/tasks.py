import logging
from celery import shared_task
from .apps_books import bulk_assign_location_asset
from .dep import define_dep_profile, sync_dep_virtual_server_devices, DEPClientError
from .models import DEPEnrollment, DEPVirtualServer, LocationAsset
from .software_updates import sync_software_updates


logger = logging.getLogger("zentral.contrib.mdm.tasks")


# DEP


@shared_task
def sync_dep_virtual_server_devices_task(dep_virtual_server_pk):
    server = DEPVirtualServer.objects.get(pk=dep_virtual_server_pk)
    result = {"dep_virtual_server": {"pk": server.pk,
                                     "name": server.name},
              "operations": {"created": 0,
                             "updated": 0}}

    def update_counters(created):
        if created:
            result["operations"]["created"] += 1
        else:
            result["operations"]["updated"] += 1

    try:
        for _, created in sync_dep_virtual_server_devices(server):
            update_counters(created)
    except DEPClientError as e:
        if e.error_code == "EXPIRED_CURSOR":
            # full sync
            for _, created in sync_dep_virtual_server_devices(server, force_fetch=True):
                update_counters(created)
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
