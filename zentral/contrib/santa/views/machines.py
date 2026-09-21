import logging
from django.core.paginator import Paginator
from django.http import Http404
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import urlencode
from django.views.generic import TemplateView
from pbac.engine import engine
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.santa.forms import EnrolledMachineSearchForm
from zentral.contrib.santa.machine_actions import actions as machine_action_classes
from zentral.contrib.santa.models import (Configuration, EnrolledMachine, MachineRule, Rule,
                                          ScopedClientMode, ScopedConfigurationItem,
                                          ScopedPathRegex, Target)
from zentral.contrib.santa.pbac import (ViewEnrolledMachineRequest, ViewScopedClientModeRequest,
                                        ViewScopedPathRegexRequest)
from zentral.utils.views import PBACViewMixin, UserPaginationListView


logger = logging.getLogger('zentral.contrib.santa.views.machines')


# a candidate is in scope, so the level that decided names the scope field of that level. A
# statement with no scope field reaches every machine, which is what decided for this one. The
# wording is the one the scope of an entry uses. Only a row with no statement at all decides
# nothing: a rule the device still has, or one its Santa version cannot evaluate
MATCH_RANK_DISPLAY = {
    ScopedConfigurationItem.RANK_SERIAL: "Serial number",
    ScopedConfigurationItem.RANK_USER: "Primary user",
    ScopedConfigurationItem.RANK_TAG: "Tag",
    ScopedConfigurationItem.RANK_ALL: "All machines",
}


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


class BaseMachineView(PBACViewMixin, TemplateView):
    """The machine the tabs share: the current enrollment, and the tab bar.

    A tab has its own URL, so its pagination and its filters live in the query string.
    """
    pbac_request_class = ViewEnrolledMachineRequest
    tab = None

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

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        urlsafe_serial_number = self.machine.get_urlsafe_serial_number()
        ctx.update({
            "machine": self.machine,
            "enrolled_machine": self.enrolled_machine,
            "enrolled_machines": self.enrolled_machines,
            "configuration": self.enrolled_machine.enrollment.configuration,
            "tab": self.tab,
            "tabs": [(name, title, reverse(f"santa:{url_name}", args=(urlsafe_serial_number,)))
                     for name, title, url_name in (("overview", "Overview", "machine"),
                                                   ("rules", "Rules", "machine_rules"),
                                                   ("path_regexes", "Path regexes", "machine_path_regexes"))],
            "actions": [
                (action.get_url(), action.get_disabled(), action.title, action.display_class)
                for action in (cls(self.machine.serial_number, self.request.user)
                               for cls in machine_action_classes)
                if action.check_permissions()
            ],
        })
        return ctx


class MachineView(BaseMachineView):
    template_name = "santa/machine_overview.html"
    tab = "overview"

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
        configuration = ctx["configuration"]
        tags = self.machine.tags
        ctx.update({
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
        return ctx


class MachineTabFiltersMixin:
    """The filter row of a machine tab: a select per filter, and a free text field.

    Each value carries its count, computed over the rows the other filters keep, so the row is
    the summary of the tab. FILTERS holds the query parameter, its label, the row key it reads,
    and the choices.
    """
    FILTERS = ()

    def _selected(self):
        return {name: self.request.GET.get(name) or "" for name, _, _, _ in self.FILTERS}

    def _matches(self, row, selected, skip=None):
        return all(selected[name] == row[key]
                   for name, _, key, _ in self.FILTERS
                   if selected[name] and name != skip)

    def _filters(self, rows, selected):
        filters = []
        for name, label, key, choices in self.FILTERS:
            others = [row for row in rows if self._matches(row, selected, skip=name)]
            values = [("", "All", len(others))]
            for value, value_label in choices():
                values.append((value, value_label, sum(1 for row in others if row[key] == value)))
            filters.append({"name": name, "label": label,
                            "selected": selected[name], "values": values})
        return filters

    def _filtered_rows(self, ctx, rows, search_keys):
        """The rows the filters and the free text field keep, with the filter row to render."""
        selected = self._selected()
        ctx["filters"] = self._filters(rows, selected)
        search = (self.request.GET.get("q") or "").strip()
        ctx["q"] = search
        rows = [row for row in rows if self._matches(row, selected)]
        if search:
            rows = [row for row in rows
                    if any(search.lower() in (row[key] or "").lower() for key in search_keys)]
        ctx["row_count"] = len(rows)
        return rows


class MachineRulesView(MachineTabFiltersMixin, BaseMachineView):
    template_name = "santa/machine_rules.html"
    tab = "rules"

    FILTERS = (
        # the query parameter, its label, the row key it reads, and the choices with their label
        ("target_type", "Target type", "target_type",
         lambda: [(t.value, t.label) for t in Target.Type.rule_order()]),
        ("policy", "Policy", "policy",
         lambda: [(str(p.value), p.label) for p in Rule.Policy.strictest_first()]),
        ("voting", "Voting", "voting",
         lambda: [("yes", "Yes"), ("no", "No")]),
        ("state", "State", "state",
         lambda: MachineRule.State.choices),
    )

    def _rules_url(self, **filters):
        query = urlencode(filters)
        configuration_pk = self.enrolled_machine.enrollment.configuration.pk
        return f"{reverse('santa:configuration_rules', args=(configuration_pk,))}?{query}"

    def _rows(self):
        rows = MachineRule.objects.rows_for_machine(self.enrolled_machine,
                                                    [t.pk for t in self.machine.tags])
        can_view_rule = self.request.user.has_perm("santa.view_rule")
        for row in rows:
            winner = row["winner"]
            row["target_url"] = reverse(row["target_type"].url_name, args=(row["identifier"],))
            row["policy"] = str(winner["policy"]) if winner else None
            row["voting"] = ("yes" if winner["is_voting_rule"] else "no") if winner else "no"
            row["policy_display"] = Rule.Policy(winner["policy"]).label if winner else None
            row["policy_version"] = winner["version"] if winner else None
            row["decided_by"] = MATCH_RANK_DISPLAY[winner["match_rank"]] if winner else None
            row["device_policy_display"] = (Rule.Policy(row["device_policy"]).label
                                            if row["device_policy"] is not None else None)
            row["rule_url"] = None
            row["rules_url"] = None
            if can_view_rule:
                if winner:
                    # the policy links to the rule that decided, alone: the type, the target and
                    # the policy. Every rule in scope has one, a rule for everyone included
                    row["rule_url"] = self._rules_url(target_type=row["target_type"].value,
                                                      identifier=row["identifier"],
                                                      policy=winner["policy"])
                if row["rules_in_configuration"] > 1:
                    # the field that decided links to every rule the configuration has for the
                    # target: the others are wider, or less strict
                    row["rules_url"] = self._rules_url(target_type=row["target_type"].value,
                                                       identifier=row["identifier"])
        return rows

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        rows = self._filtered_rows(ctx, self._rows(), ("identifier",))
        page = Paginator(rows, self.request.user.items_per_page).get_page(self.request.GET.get("page"))
        ctx["page_obj"] = page
        ctx["rows"] = page.object_list
        if page.has_next():
            ctx["next_url"] = self._page_url(page.next_page_number())
        if page.has_previous():
            ctx["previous_url"] = self._page_url(page.previous_page_number())
        return ctx

    def _page_url(self, page_number):
        qd = self.request.GET.copy()
        qd["page"] = page_number
        return f"?{qd.urlencode()}"


class MachinePathRegexesView(MachineTabFiltersMixin, BaseMachineView):
    template_name = "santa/machine_path_regexes.html"
    tab = "path_regexes"

    FILTERS = (
        ("policy", "Policy", "policy", lambda: ScopedPathRegex.Policy.choices),
    )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        configuration = ctx["configuration"]
        winners = Configuration.resolve_scoped_path_regexes(
            ScopedPathRegex.objects.for_machine(
                configuration,
                self.enrolled_machine.serial_number,
                self.enrolled_machine.primary_user,
                [t.pk for t in self.machine.tags],
            ).prefetch_related("tags", "excluded_tags")
        )
        # a template cannot build a PBAC request
        requests = [ViewScopedPathRegexRequest(self.request.user, w) for w in winners]
        engine.authorize_requests(requests)
        visible_pks = {w.pk for w, r in zip(winners, requests) if r.is_authorized}
        can_view_configuration = self.request.user.has_perm("santa.view_configuration")
        # the parts of each pattern Zentral composes, in the order it composes them: the pattern
        # of the configuration first, then the entries. A pattern is what the machine enforces, so
        # every part is here. Only the name of an entry, and the link to it, need its permission
        rows = []
        for policy, baseline in ((ScopedPathRegex.Policy.ALLOW, configuration.allowed_path_regex),
                                 (ScopedPathRegex.Policy.BLOCK, configuration.blocked_path_regex)):
            if baseline:
                rows.append({"name": None, "regex": baseline, "policy": policy.value,
                             "policy_display": policy.label,
                             "decided_by": "Configuration", "url": None})
            for winner in winners:
                if winner.policy != policy:
                    continue
                visible = winner.pk in visible_pks
                rows.append({"name": winner.name if visible else None,
                             "regex": winner.regex,
                             "policy": winner.policy,
                             "policy_display": winner.get_policy_display(),
                             "decided_by": MATCH_RANK_DISPLAY[winner.match_rank],
                             "url": (winner.get_absolute_url()
                                     if visible and can_view_configuration else None)})
        ctx["rows"] = self._filtered_rows(ctx, rows, ("name", "regex"))
        return ctx
