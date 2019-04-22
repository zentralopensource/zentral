import logging
import dateutil.parser
from django.utils import timezone
from zentral.core.queues import queues
from .apns import APNSClient
from .models import EnrolledDevice


logger = logging.getLogger("zentral.contrib.mdm.workers")


class DeviceNotificationSender(object):
    name = "mdm device notification sender"
    input_queue_name = "mdm_device_notifications"

    def __init__(self):
        self.apns_clients = {}

    def get_apns_client(self, push_certificate):
        client = self.apns_clients.get(push_certificate)
        if not client:
            client = APNSClient(push_certificate)
            self.apns_clients[push_certificate] = client
        return client

    def send_enrolled_device_notification(self, enrolled_device):
        if not enrolled_device.can_be_poked():
            logger.error("Cannot send notification to enrolled device %s", enrolled_device.pk)
            return
        client = self.get_apns_client(enrolled_device.push_certificate)
        return client.send_device_notification(enrolled_device)

    def process_raw_event(self, raw_event):
        not_before = raw_event.pop("not_before", None)
        if not_before:
            not_before_dt = dateutil.parser.parse(not_before)
            if not_before_dt > timezone.now():
                err_msg = "Message cannot be processed before {}".format(not_before)
                raise ValueError(err_msg)
        # get enrolled devices pk
        try:
            enrolled_device_pk_list = [int(pk) for pk in raw_event["enrolled_device_pk_list"]]
        except (KeyError, TypeError, ValueError):
            logger.error("Could not read enrolled device pk list")
            return

        for enrolled_device in (EnrolledDevice.objects.select_related("push_certificate")
                                                      .filter(pk__in=enrolled_device_pk_list)):
            event = self.send_enrolled_device_notification(enrolled_device)
            if event:
                yield event


def get_workers():
    yield queues.get_preprocess_worker(DeviceNotificationSender())
