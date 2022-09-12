from django.core.management.base import BaseCommand
from zentral.contrib.mdm.models import EnrolledDevice
from zentral.contrib.mdm.apns import send_enrolled_device_notification


class Command(BaseCommand):
    help = 'Send device notification'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle(self, *args, **kwargs):
        for d in EnrolledDevice.objects.select_related("push_certificate").all():
            self.stdout.write(f"Device {d.serial_number} {d.udid}", ending=" ")
            if not d.can_be_poked():
                self.stdout.write("Skipped")
                continue
            success = False
            try:
                success = send_enrolled_device_notification(d)
            except Exception:
                pass
            if success:
                self.stdout.write("OK")
            else:
                self.stdout.write("Failure")
