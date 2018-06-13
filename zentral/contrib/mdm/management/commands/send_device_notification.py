from django.core.management.base import BaseCommand
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.apns import APNSClient


class Command(BaseCommand):
    help = 'Send device notification'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.apns_clients = {}

    def get_apns_client(self, enrolled_device):
        push_certificate = enrolled_device.push_certificate
        if push_certificate not in self.apns_clients:
            self.apns_clients[push_certificate] = APNSClient(push_certificate)
        return self.apns_clients[push_certificate]

    def handle(self, *args, **kwargs):
        for d in EnrolledDevice.objects.filter(token__isnull=False):
            print("Device", d.serial_number, d.udid)
            c = self.get_apns_client(d)
            event = c.send_device_notification(d)
            print("=>", event.serialize().get("status", "STATUS UNKNOWN"))
