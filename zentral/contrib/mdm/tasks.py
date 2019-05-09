import logging
from celery import shared_task
from .apns import APNSClient
from .models import EnrolledDevice


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
