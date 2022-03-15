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

    def __init__(self, serial_number, user):
        self.user = user
        enrolled_machines = EnrolledMachine.objects.get_for_serial_number(serial_number)
        count = len(enrolled_machines)
        if count > 1:
            self.err_message = f"{count} machines found!!!"
        if count > 0:
            self.enrolled_machine = enrolled_machines[0]

    def render(self):
        ctx = {"err_message": self.err_message}
        if self.enrolled_machine:
            ctx.update({
                "enrolled_machine": self.enrolled_machine,
                "err_message": self.err_message,
            })
            if self.user.has_perm("osquery.view_configuration"):
                ctx["configuration"] = self.enrolled_machine.enrollment.configuration
        return render_to_string(self.template_name, ctx)
