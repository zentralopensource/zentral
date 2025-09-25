import logging
from django.template.loader import render_to_string
from zentral.contrib.mdm.models import EnrolledDevice


logger = logging.getLogger('zentral.contrib.mdm.views.inventory')


# inventory machine subview


class InventoryMachineSubview:
    template_name = "mdm/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.mdm", "MDM")
    err_message = None
    enrolled_machine = None

    def __init__(self, serial_number, user):
        self.user = user
        self.enrolled_devices = list(
            EnrolledDevice.objects.filter(serial_number=serial_number)
                                  .prefetch_related("users")
                                  .order_by("-updated_at")
        )
        count = len(self.enrolled_devices)
        if count > 1:
            self.err_message = f"{count} enrolled devices found!!!"

    def render(self):
        enrolled_devices = []
        for enrolled_device in self.enrolled_devices:
            enrolled_users = list(enrolled_device.users.all())
            enrolled_devices.append((enrolled_device, enrolled_users))
        ctx = {"err_message": self.err_message,
               "enrolled_devices": enrolled_devices,
               "can_view_device": self.user.has_perm("mdm.view_enrolleddevice"),
               "can_view_user": self.user.has_perm("mdm.view_enrolleduser"),
               }
        return render_to_string(self.template_name, ctx)
