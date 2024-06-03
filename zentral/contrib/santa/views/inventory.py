import logging
from django.template.loader import render_to_string
from zentral.contrib.santa.models import EnrolledMachine


logger = logging.getLogger('zentral.contrib.santa.views.inventory')


class InventoryMachineSubview:
    template_name = "santa/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.santa", "Santa")
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
            em = self.enrolled_machine
            ctx.update({
                "enrolled_machine": em,
                "err_message": self.err_message,
                "binary_rule_count": "-" if em.binary_rule_count is None else em.binary_rule_count,
                "cdhash_rule_count": "-" if em.cdhash_rule_count is None else em.cdhash_rule_count,
                "certificate_rule_count": "-" if em.certificate_rule_count is None else em.certificate_rule_count,
                "compiler_rule_count": "-" if em.compiler_rule_count is None else em.compiler_rule_count,
                "signingid_rule_count": "-" if em.signingid_rule_count is None else em.signingid_rule_count,
                "transitive_rule_count": "-" if em.transitive_rule_count is None else em.transitive_rule_count,
                "teamid_rule_count": "-" if em.teamid_rule_count is None else em.teamid_rule_count,
            })
            if self.user.has_perm("santa.view_configuration"):
                ctx["configuration"] = em.enrollment.configuration
        return render_to_string(self.template_name, ctx)
