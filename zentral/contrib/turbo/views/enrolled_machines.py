from django.contrib.auth.mixins import PermissionRequiredMixin
from django.db.models import F
from django.http import Http404
from django.urls import reverse
from django.views.generic import TemplateView
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.views import CreateViewWithAudit
from ..forms import EnrolledMachineSearchForm, MachineOneTimeJobForm
from ..models import EnrolledMachine, Job, OneTimeJob, OneTimeJobMachine, RecurringJobMachine
from ..pbac import can_create_one_time_job, check_create_one_time_job
from .base import SearchFormListView


def serial_number_from_kwargs(kwargs):
    # the admin URLs carry the url-safe serial (base64url when the serial is not url-safe); a
    # hand-crafted junk value that will not decode is a 404, not a 500
    try:
        return MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"]).serial_number
    except ValueError:
        raise Http404


class EnrolledMachineListView(SearchFormListView):
    permission_required = "turbo.view_enrolledmachine"
    model = EnrolledMachine
    search_form_class = EnrolledMachineSearchForm


class EnrolledMachineDetailView(PermissionRequiredMixin, TemplateView):
    permission_required = "turbo.view_enrolledmachine"
    template_name = "turbo/enrolledmachine_detail.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        serial_number = serial_number_from_kwargs(kwargs)
        enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__configuration")
                                                   .filter(serial_number=serial_number).first())
        if enrolled_machine is None:
            raise Http404
        ctx["serial_number"] = serial_number
        ctx["urlsafe_serial_number"] = kwargs["urlsafe_serial_number"]
        ctx["enrolled_machine"] = enrolled_machine
        ctx["configuration"] = enrolled_machine.enrollment.configuration
        # the button asks the scheduling action with the configuration and no job: there is no
        # permission left for the template to read
        ctx["can_create_one_time_job"] = can_create_one_time_job(
            self.request.user, enrolled_machine.enrollment.configuration)
        ctx["machine_url"] = MetaMachine(serial_number).get_absolute_url()
        # live rows first (removed_at null), then removed ones; freshest activity on top
        order = (F("removed_at").asc(nulls_first=True), F("last_result_at").desc(nulls_last=True))
        one_time = (
            OneTimeJobMachine.objects
            .filter(serial_number=serial_number)
            .select_related(*Job.definition_relations("one_time_job__job__"))
            .order_by(*order)
        )
        recurring = (
            RecurringJobMachine.objects
            .filter(serial_number=serial_number)
            .select_related(*Job.definition_relations("recurring_job__job__"))
            .order_by(*order)
        )
        kind = self.request.GET.get("kind") or ""
        if kind not in Job.Kind.values:
            kind = ""
        if kind:
            one_time = one_time.filter(one_time_job__job__kind=kind)
            recurring = recurring.filter(recurring_job__job__kind=kind)
        ctx["one_time_job_machines"] = one_time
        ctx["recurring_job_machines"] = recurring
        ctx["kind_choices"] = Job.Kind.choices
        ctx["selected_kind"] = kind
        return ctx


class ScheduleMachineOneTimeJobView(PermissionRequiredMixin, CreateViewWithAudit):
    # The scheduling action takes the configuration as its resource, and the configuration is only
    # known once the serial resolves — so it cannot be the gate that runs first. view_enrolledmachine
    # is: a 404 (unknown serial) and a 403 (no access) must not be distinguishable to someone who
    # cannot list enrolled machines in the first place.
    permission_required = "turbo.view_enrolledmachine"
    model = OneTimeJob
    form_class = MachineOneTimeJobForm
    template_name = "turbo/machineonetimejob_form.html"

    def dispatch(self, request, *args, **kwargs):
        if not self.has_permission():
            return self.handle_no_permission()
        self.serial_number = serial_number_from_kwargs(kwargs)
        self.enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__configuration")
                                                        .filter(serial_number=self.serial_number).first())
        if self.enrolled_machine is None:
            raise Http404
        self.configuration = self.enrolled_machine.enrollment.configuration
        # the coarse question, now that there is a configuration to ask it about
        check_create_one_time_job(request, self.configuration)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["configuration"] = self.configuration
        kwargs["serial_number"] = self.serial_number
        kwargs["user"] = self.request.user
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["serial_number"] = self.serial_number
        ctx["urlsafe_serial_number"] = MetaMachine.make_urlsafe_serial_number(self.serial_number)
        ctx["configuration"] = self.configuration
        return ctx

    def form_valid(self, form):
        check_create_one_time_job(self.request, self.configuration, form.cleaned_data["job"])
        return super().form_valid(form)

    def get_success_url(self):
        return reverse("turbo:enrolled_machine",
                       args=(MetaMachine.make_urlsafe_serial_number(self.serial_number),))
