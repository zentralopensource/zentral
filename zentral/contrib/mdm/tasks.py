import logging
from celery import shared_task
from .dep import sync_dep_virtual_server_devices, DEPClientError
from .models import DEPVirtualServer
from .software_updates import sync_software_updates


logger = logging.getLogger("zentral.contrib.mdm.tasks")


#
# DEP
#


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


#
# Software updates
#

@shared_task
def sync_software_updates_task():
    return sync_software_updates()
