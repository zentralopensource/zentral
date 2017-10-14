from django.core.management.base import BaseCommand
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.apns import send_device_notification


class Command(BaseCommand):
    help = 'Send device notification'

    def handle(self, *args, **kwargs):
        for d in EnrolledDevice.objects.filter(token__isnull=False):
            print("Device", d.serial_number, d.udid)
            send_device_notification(d)
