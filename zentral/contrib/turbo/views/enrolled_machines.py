from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import F
from django.http import Http404
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.views import CreateViewWithAudit
from ..forms import EnrolledMachineSearchForm, MachineOneTimeJobForm
from ..models import EnrolledMachine, Job, MachineJobStatus, OneTimeJob
from .base import SearchFormListView


class EnrolledMachineListView(SearchFormListView):
    permission_required = "turbo.view_enrolledmachine"
    model = EnrolledMachine
    search_form_class = EnrolledMachineSearchForm


class EnrolledMachineDetailView(PermissionRequiredMixin, TemplateView):
    permission_required = "turbo.view_enrolledmachine"
    template_name = "turbo/enrolledmachine_detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        serial_number = kwargs["serial_number"]
        enrolled_machine = EnrolledMachine.objects.latest_for_serial_number(serial_number)
        if enrolled_machine is None:
            raise Http404
        ctx["serial_number"] = serial_number
        ctx["enrolled_machine"] = enrolled_machine
        ctx["configuration"] = enrolled_machine.enrollment.configuration
        ctx["machine_url"] = MetaMachine(serial_number).get_absolute_url()
        statuses = (
            MachineJobStatus.objects
            .filter(serial_number=serial_number)
            .select_related("job__script", "job__mscp_check", "one_time_job")
            # live rows first (removed_at null), then removed ones; freshest activity on top
            .order_by(F("removed_at").asc(nulls_first=True), F("last_result_at").desc(nulls_last=True))
        )
        kind = self.request.GET.get("kind") or ""
        if kind not in Job.Kind.values:
            kind = ""
        if kind:
            statuses = statuses.filter(job__kind=kind)
        ctx["machine_job_statuses"] = statuses
        ctx["kind_choices"] = Job.Kind.choices
        ctx["selected_kind"] = kind
        return ctx


class ScheduleMachineOneTimeJobView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "turbo.add_onetimejob"
    model = OneTimeJob
    form_class = MachineOneTimeJobForm
    template_name = "turbo/machineonetimejob_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.serial_number = kwargs["serial_number"]
        self.enrolled_machine = EnrolledMachine.objects.latest_for_serial_number(self.serial_number)
        if self.enrolled_machine is None:
            raise Http404
        self.configuration = self.enrolled_machine.enrollment.configuration
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        kwargs["serial_number"] = self.serial_number
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["serial_number"] = self.serial_number
        ctx["configuration"] = self.configuration
        return ctx

    def get_success_url(self):
        return reverse("turbo:enrolled_machine", args=(self.serial_number,))
