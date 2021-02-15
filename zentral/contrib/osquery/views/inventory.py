import logging
from django.template.loader import render_to_string
from zentral.contrib.osquery.models import EnrolledMachine


logger = logging.getLogger("zentral.contrib.osquery.views.inventory")


# inventory machine subview


class InventoryMachineSubview:
    template_name = "osquery/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.osquery", "osquery")
    err_message = None
    enrolled_machine = None

    def __init__(self, serial_number):
        qs = (EnrolledMachine.objects.select_related("enrollment__configuration")
                                     .filter(serial_number=serial_number).order_by("-updated_at"))
        count = qs.count()
        if count > 1:
            self.err_message = f"{count} machines found!!!"
        if count > 0:
            self.enrolled_machine = qs.first()

    def render(self):
        ctx = {"err_message": self.err_message}
        if self.enrolled_machine:
            em = self.enrolled_machine
            ctx.update({
                "enrolled_machine": em,
                "configuration": em.enrollment.configuration,
                "err_message": self.err_message,
            })
        return render_to_string(self.template_name, ctx)
