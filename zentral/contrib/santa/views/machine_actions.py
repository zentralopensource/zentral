import logging
from django.contrib import messages
from django.db import transaction
from django.http import Http404
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.santa.models import EnrolledMachine
from zentral.contrib.santa.pbac import ForceCleanSyncRequest
from zentral.core.events.base import AuditEvent
from zentral.utils.views import PBACViewMixin


logger = logging.getLogger('zentral.contrib.santa.views.machine_actions')


class BaseCleanSyncView(PBACViewMixin, TemplateView):
    """Confirm and apply a change to the clean sync queued for a machine.

    A subclass provides get_sync_type(), update_enrolled_machine() and
    get_success_message().
    """
    pbac_request_class = ForceCleanSyncRequest

    def get_pbac_request_kwargs(self, kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        enrolled_machines = EnrolledMachine.objects.get_for_serial_number(self.machine.serial_number)
        if not enrolled_machines:
            raise Http404("Machine not enrolled")
        self.enrolled_machine = enrolled_machines[0]
        return {"machine": self.machine,
                "enrolled_machine": self.enrolled_machine,
                "sync_type": self.get_sync_type()}

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["machine"] = self.machine
        ctx["enrolled_machine"] = self.enrolled_machine
        return ctx

    def post(self, request, *args, **kwargs):
        prev_value = self.enrolled_machine.serialize_for_event()
        if self.update_enrolled_machine():
            def on_commit_callback():
                AuditEvent.build_from_request_and_instance(
                    request, self.enrolled_machine,
                    action=AuditEvent.Action.UPDATED,
                    prev_value=prev_value,
                    machine_serial_number=self.enrolled_machine.serial_number,
                ).post()

            transaction.on_commit(on_commit_callback)
        messages.info(request, self.get_success_message())
        return redirect(self.machine.get_absolute_url())


class ForceMachineCleanSyncView(BaseCleanSyncView):
    template_name = "santa/force_machine_clean_sync_confirm.html"

    def get_sync_type(self):
        # NORMAL is not a clean sync, and queueing one would mean nothing
        if self.kwargs["sync_type"] not in EnrolledMachine.SyncType.clean_values():
            raise Http404("Unknown sync type")
        return EnrolledMachine.SyncType(self.kwargs["sync_type"])

    def update_enrolled_machine(self):
        return self.enrolled_machine.force_sync_type(self.get_sync_type(), timezone.now())

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["sync_type"] = self.get_sync_type()
        return ctx

    def get_success_message(self):
        return (f"{self.get_sync_type().label} sync queued for machine {self.machine.serial_number}."
                " It will be performed during the next Santa preflight.")


class CancelMachineCleanSyncView(BaseCleanSyncView):
    template_name = "santa/cancel_machine_clean_sync_confirm.html"

    def get_sync_type(self):
        # a cancellation is authorized against the sync type it takes back
        return self.enrolled_machine.forced_sync_type or EnrolledMachine.SyncType.CLEAN

    def update_enrolled_machine(self):
        return self.enrolled_machine.clear_forced_sync_type()

    def get_success_message(self):
        return f"Queued clean sync cancelled for machine {self.machine.serial_number}."
