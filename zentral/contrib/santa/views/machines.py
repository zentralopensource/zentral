import logging
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.views.generic import TemplateView
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.santa.forms import EnrolledMachineSearchForm
from zentral.contrib.santa.machine_actions import actions as machine_action_classes
from zentral.contrib.santa.models import Configuration, EnrolledMachine, ScopedClientMode
from zentral.contrib.santa.pbac import ViewEnrolledMachineRequest, ViewScopedClientModeRequest
from zentral.utils.views import PBACViewMixin, UserPaginationListView


logger = logging.getLogger('zentral.contrib.santa.views.machines')


class MachineListView(PBACViewMixin, UserPaginationListView):
    pbac_request_class = ViewEnrolledMachineRequest
    model = EnrolledMachine
    template_name = "santa/machine_list.html"

    def get_pbac_request_kwargs(self, kwargs):
        return {}

    def get(self, request, *args, **kwargs):
        self.form = EnrolledMachineSearchForm(request.GET)
        self.form.is_valid()
        redirect_to = self.form.get_redirect_to()
        if redirect_to:
            return redirect(redirect_to)
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["form"] = self.form
        page = ctx["page_obj"]
        reset_link = None
        if page.number > 1:
            qd = self.request.GET.copy()
            qd.pop("page", None)
            reset_link = "?{}".format(qd.urlencode())
        if self.form.has_changed():
            ctx["breadcrumbs"] = [(reverse("santa:machines"), "Machines"), (reset_link, "Search")]
        else:
            ctx["breadcrumbs"] = [(reset_link, "Machines")]
        return ctx


class MachineView(PBACViewMixin, TemplateView):
    pbac_request_class = ViewEnrolledMachineRequest
    template_name = "santa/machine_overview.html"

    def get_pbac_request_kwargs(self, kwargs):
        return {}

    def get(self, request, *args, **kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        # the page describes the enrollment the device talks to. The older rows are its history
        self.enrolled_machines = list(EnrolledMachine.objects.for_serial_number(self.machine.serial_number))
        if not self.enrolled_machines:
            raise Http404("Machine not enrolled")
        self.enrolled_machine = self.enrolled_machines[0]
        return super().get(request, *args, **kwargs)

    def _client_mode(self, tag_ids):
        """The entry that decides the mode for the machine, and whether the user may view it."""
        winner = Configuration.resolve_scoped_client_mode(
            ScopedClientMode.objects.for_machine(
                self.enrolled_machine.enrollment.configuration,
                self.enrolled_machine.serial_number,
                self.enrolled_machine.primary_user,
                tag_ids,
            )
        )
        if winner is None:
            return None, False
        # a template cannot build a PBAC request
        pbac_request = ViewScopedClientModeRequest(self.request.user, winner)
        engine.authorize_request(pbac_request)
        return winner, pbac_request.is_authorized

    def _source(self, configuration, entry, entry_visible):
        """Where a resolved value comes from: the entry that decided, or the configuration.

        The link goes to the entry in the configuration page, or to the configuration itself.
        """
        if entry is not None:
            label, url = "Scoped client mode", entry.get_absolute_url() if entry_visible else None
        else:
            label, url = "Configuration", reverse("santa:configuration", args=(configuration.pk,))
        if not self.request.user.has_perm("santa.view_configuration"):
            url = None
        return label, url

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        configuration = self.enrolled_machine.enrollment.configuration
        tags = self.machine.tags
        ctx.update({
            "machine": self.machine,
            "enrolled_machine": self.enrolled_machine,
            "enrolled_machines": self.enrolled_machines,
            "configuration": configuration,
            "tags": tags,
            # the resolution the preflight answers with, from the code that answers it
            "sync_config": configuration.get_sync_server_config(
                self.enrolled_machine, self.enrolled_machine.get_comparable_santa_version()
            ),
        })
        # the configured mode comes from the preflight answer, in its display form: the wire value
        # next to the one the machine reported would be two spellings of one mode
        ctx["configured_client_mode"] = {
            configuration.get_preflight_client_mode(value): label
            for value, label in Configuration.CLIENT_MODE_CHOICES
        }[ctx["sync_config"]["client_mode"]]
        ctx["reported_rule_counts"] = [
            (label, getattr(self.enrolled_machine, f"{prefix}_rule_count"))
            for prefix, label in (("binary", "binary"), ("cdhash", "cdhash"),
                                  ("certificate", "certificate"), ("signingid", "signing ID"),
                                  ("teamid", "Team ID"), ("compiler", "compiler"),
                                  ("transitive", "transitive"))
        ]
        # the entry that decided is only linked to a user that may view it
        winner, winner_visible = self._client_mode([t.pk for t in tags])
        ctx["client_mode_source"] = self._source(configuration, winner, winner_visible)
        # the entry sets the button only when its source is not Inherit
        button_entry = winner if (winner is not None
                                  and winner.event_detail_source != ScopedClientMode.EventDetailSource.INHERIT
                                  ) else None
        ctx["event_detail_source"] = (button_entry or configuration).get_event_detail_source_display()
        ctx["event_detail_source_link"] = self._source(configuration, button_entry, winner_visible)
        ctx["actions"] = [
            (action.get_url(), action.get_disabled(), action.title, action.display_class)
            for action in (cls(self.machine.serial_number, self.request.user)
                           for cls in machine_action_classes)
            if action.check_permissions()
        ]
        return ctx
