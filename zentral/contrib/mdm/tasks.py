import logging
from celery import shared_task
from .apns import APNSClient
from .dep import sync_dep_virtual_server_devices, DEPClientError
from .models import DEPVirtualServer, EnrolledDevice


logger = logging.getLogger("zentral.contrib.mdm.tasks")


CACHED_APNS_CLIENTS = {}


def get_apns_client(push_certificate):
    client = CACHED_APNS_CLIENTS.get(push_certificate)
    if not client:
        client = APNSClient(push_certificate)
        CACHED_APNS_CLIENTS[push_certificate] = client
    return client


@shared_task(ignore_result=True)
def send_enrolled_devices_notifications_task(enrolled_device_pk_list):
    for enrolled_device in (EnrolledDevice.objects.select_related("push_certificate")
                                                  .filter(pk__in=enrolled_device_pk_list)):
        if not enrolled_device.can_be_poked():
            logger.error("Cannot send notification to enrolled device %s", enrolled_device.pk)
            return
        client = get_apns_client(enrolled_device.push_certificate)
        event = client.send_device_notification(enrolled_device)
        if event:
            event.post()


def send_enrolled_device_notification(enrolled_device, delay=0):
    send_enrolled_devices_notifications_task.apply_async(
        ([enrolled_device.pk],),
        countdown=delay
    )


def send_mbu_enrolled_devices_notifications(mbu):
    send_enrolled_devices_notifications_task.apply_async(
        ([d.pk for d in EnrolledDevice.objects.active_in_mbu(mbu)],)
    )


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
