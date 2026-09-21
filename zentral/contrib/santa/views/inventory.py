import logging
from django.template.loader import render_to_string
from django.urls import reverse
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.santa.models import EnrolledMachine
from zentral.contrib.santa.pbac import ViewEnrolledMachineRequest


logger = logging.getLogger('zentral.contrib.santa.views.inventory')


class InventoryMachineSubview:
    template_name = "santa/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.santa", "Santa")
    enrolled_machine = None

    def __init__(self, serial_number, user):
        self.user = user
        self.serial_number = serial_number
        enrolled_machines = list(EnrolledMachine.objects.for_serial_number(serial_number))
        if enrolled_machines:
            # the row the device talks to. The others are the history of the machine: it
            # enrolled through another enrollment, or its hardware UUID changed
            self.enrolled_machine = enrolled_machines[0]
            self.other_enrollment_count = len(enrolled_machines) - 1

    def render(self):
        ctx = {}
        if self.enrolled_machine:
            em = self.enrolled_machine
            ctx.update({
                "enrolled_machine": em,
                "serial_number": self.serial_number,
                "other_enrollment_count": self.other_enrollment_count,
                # a template cannot tell an unknown state from a mismatch
                "sync_ok": "-" if em.last_sync_ok is None else "yes" if em.last_sync_ok else "no",
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
            # a template cannot build a PBAC request
            pbac_request = ViewEnrolledMachineRequest(self.user)
            engine.authorize_request(pbac_request)
            if pbac_request.is_authorized:
                ctx["machine_url"] = reverse(
                    "santa:machine",
                    args=(MetaMachine.make_urlsafe_serial_number(self.serial_number),)
                )
        return render_to_string(self.template_name, ctx)
