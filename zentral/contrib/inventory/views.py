from datetime import datetime, timedelta
from importlib import import_module
import logging
from math import ceil
from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models import F
from django.urls import reverse, reverse_lazy
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.utils.functional import SimpleLazyObject
from django.views.generic import DeleteView, DetailView, FormView, ListView, TemplateView, View
from zentral.conf import settings
from zentral.core.compliance_checks import compliance_check_class_from_model
from zentral.core.compliance_checks.forms import ComplianceCheckForm
from zentral.core.compliance_checks.models import Status
from zentral.core.incidents.models import MachineIncident
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.text import encode_args
from zentral.utils.terraform import build_config_response
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit,
                                 UserPaginationListView, UserPaginationMixin)
from .compliance_checks import InventoryJMESPathCheck
from .events import JMESPathCheckCreated, JMESPathCheckUpdated, JMESPathCheckDeleted
from .forms import (MetaBusinessUnitForm,
                    MetaBusinessUnitSearchForm, MachineGroupSearchForm,
                    MergeMBUForm, AddMBUTagForm, AddMachineTagForm,
                    CreateTagForm, UpdateTagForm,
                    AndroidAppSearchForm, DebPackageSearchForm, IOSAppSearchForm,
                    MacOSAppSearchForm, ProgramsSearchForm,
                    JMESPathCheckForm, JMESPathCheckDevToolForm, Source)
from .models import (BusinessUnit,
                     MetaBusinessUnit, MachineGroup,
                     MetaMachine,
                     MetaBusinessUnitTag, Tag, Taxonomy,
                     JMESPathCheck)
from .terraform import iter_compliance_check_resources
from .utils import (AndroidAppFilter, AndroidAppFilterForm,
                    BundleFilter, BundleFilterForm,
                    ComplianceCheckStatusFilter, ComplianceCheckStatusFilterForm,
                    DebPackageFilter, DebPackageFilterForm,
                    MachineGroupFilter, MetaBusinessUnitFilter,
                    IOSAppFilter, IOSAppFilterForm,
                    ProgramFilter, ProgramFilterForm,
                    SourceFilter,
                    MSQuery,
                    remove_machine_tags)


logger = logging.getLogger("zentral.contrib.inventory.views")


# Machine subviews contributed by the different apps.
#
# A machine subview is a piece of view that is displayed
# in the tab info for a given source.


def _load_source_machine_subviews():
    result = {}
    for app in settings["apps"]:
        try:
            subview = getattr(import_module(f"{app}.views"), "InventoryMachineSubview")
        except (ModuleNotFoundError, AttributeError):
            pass
        else:
            result.setdefault(subview.source_key, []).append(subview)
    return result


source_machine_subviews = SimpleLazyObject(_load_source_machine_subviews)


def _get_source_machine_subview(source, serial_number, user):
    source_key = (source.module, source.name)
    return [subview(serial_number, user) for subview in source_machine_subviews.get(source_key, [])]


# Machine actions contributed by the different apps.
#
# A machine action is a link to a page where an action can be
# triggered for a give machine. The Zentral apps can offer actions
# that are filtered and displayed in the `Action` dropdown menu.


def _load_machine_actions():
    result = {}
    for app in settings["apps"]:
        try:
            actions = getattr(import_module(f"{app}.machine_actions"), "actions")
        except (ModuleNotFoundError, AttributeError):
            pass
        else:
            for action in actions:
                result.setdefault(action.category or "", []).append(action)
    return result


machine_actions = SimpleLazyObject(_load_machine_actions)


def _get_machine_actions(serial_number, user):
    actions = []
    for category in sorted(machine_actions.keys()):
        category_actions = []
        for action_class in machine_actions[category]:
            action = action_class(serial_number, user)
            if action.check_permissions():
                category_actions.append((
                    action.get_url(),
                    action.get_disabled(),
                    action.title,
                    action.display_class,
                ))
        if category_actions:
            actions.append((category, category_actions))
    return actions


# The views


class MachineListView(PermissionRequiredMixin, UserPaginationMixin, TemplateView):
    template_name = "inventory/machine_list.html"
    last_seen_session_key = "inventory_last_last_seen"
    last_seen_default = "7d"
    force_search = False
    filter_forms = (
        ("android_app_filter_form", AndroidAppFilterForm, "aaf"),
        ("bundle_filter_form", BundleFilterForm, "bf"),
        ("deb_package_filter_form", DebPackageFilterForm, "dpf"),
        ("ios_app_filter_form", IOSAppFilterForm, "iaf"),
        ("program_filter_form", ProgramFilterForm, "pf"),
        ("compliance_check_status_filter_form", ComplianceCheckStatusFilterForm, "ccsf")
    )

    def get_object(self, **kwargs):
        return None

    def get_msquery(self, request):
        request_dict = request.GET.copy()
        if "ls" not in request_dict:
            request_dict["ls"] = request.session.setdefault(self.last_seen_session_key, self.last_seen_default)
        return MSQuery(request_dict, paginate_by=self.get_paginate_by())

    def get(self, request, *args, **kwargs):
        try:
            self.object = self.get_object(**kwargs)
        except ObjectDoesNotExist:
            raise Http404
        self.msquery = self.get_msquery(request)
        redirect_url = self.msquery.redirect_url()
        if redirect_url:
            return HttpResponseRedirect(redirect_url)
        ls = self.msquery.query_dict.get("ls")
        if ls:
            request.session[self.last_seen_session_key] = ls
        elif self.last_seen_session_key in request.session:
            del request.session[self.last_seen_session_key]
        return super().get(request, *args, **kwargs)

    def get_list_title(self):
        return ""

    def get_breadcrumbs(self, **kwargs):
        return []

    def get_forms(self):
        forms = {}
        for key, filter_form_class, prefix in self.filter_forms:
            kwargs = {"prefix": prefix, "msquery": self.msquery}
            if self.request.method == "POST" and self.request.POST.get("filter_key") == key:
                kwargs["data"] = self.request.POST
            forms[key] = filter_form_class(**kwargs)
        return forms

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        # object
        ctx["object"] = self.object
        ctx['object_list_title'] = self.get_list_title()
        # msquery
        ctx["msquery"] = self.msquery
        # pagination / machines
        ctx["grouping_links"] = self.msquery.grouping_links()

        if self.force_search or self.msquery.is_search:
            ctx["machines"] = self.msquery.fetch()
            if self.msquery.page > 1:
                qd = self.request.GET.copy()
                qd['page'] = self.msquery.page - 1
                ctx['previous_url'] = "?{}".format(qd.urlencode())
            if self.msquery.page * self.msquery.paginate_by < self.msquery.count():
                qd = self.request.GET.copy()
                qd['page'] = self.msquery.page + 1
                ctx['next_url'] = "?{}".format(qd.urlencode())

        # search form hidden values
        search_form_qd = self.request.GET.copy()
        for key in [f.get_query_kwarg() for f in self.msquery.filters if f.free_input]:
            search_form_qd.pop(key, None)
        ctx["search_form_qd"] = search_form_qd

        # breadcrumbs
        breadcrumbs = self.get_breadcrumbs(**kwargs)
        if breadcrumbs and (self.force_search or self.msquery.is_search):
            num_pages = ceil(max(self.msquery.count(), 1) / self.msquery.paginate_by)
            _, anchor_text = breadcrumbs.pop()
            reset_qd = self.request.GET.copy()
            reset_qd.pop('page', None)
            reset_link = "?{}".format(reset_qd.urlencode())
            breadcrumbs.extend([(reset_link, anchor_text),
                                (None, "page {} of {}".format(self.msquery.page, num_pages))])
        ctx['breadcrumbs'] = breadcrumbs

        msquery_cqd = self.msquery.get_canonical_query_dict()
        ctx['export_links'] = []
        for fmt in ("xlsx", "zip"):
            export_qd = msquery_cqd.copy()
            export_qd["export_format"] = fmt
            ctx['export_links'].append((fmt,
                                        "{}?{}".format(reverse("inventory_api:machines_export"),
                                                       export_qd.urlencode())))
        # filter forms
        for key, form in self.get_forms().items():
            if key not in kwargs:
                ctx[key] = form
        return ctx

    def form_invalid(self, **kwargs):
        kwargs["filter_form_errors"] = True
        return self.render_to_response(self.get_context_data(**kwargs))

    def android_app_filter_form_valid(self, form):
        display_name = form.cleaned_data.get("display_name")
        self.msquery.add_filter(AndroidAppFilter, display_name=display_name)

    def bundle_filter_form_valid(self, form):
        f_kwargs = {}
        bundle_id = form.cleaned_data.get("bundle_id")
        bundle_name = form.cleaned_data.get("bundle_name")
        if bundle_id:
            f_kwargs["bundle_id"] = bundle_id
        elif bundle_name:
            f_kwargs["bundle_name"] = bundle_name
        self.msquery.add_filter(BundleFilter, **f_kwargs)

    def deb_package_filter_form_valid(self, form):
        name = form.cleaned_data.get("name")
        self.msquery.add_filter(DebPackageFilter, name=name)

    def ios_app_filter_form_valid(self, form):
        name = form.cleaned_data.get("name")
        self.msquery.add_filter(IOSAppFilter, name=name)

    def program_filter_form_valid(self, form):
        name = form.cleaned_data.get("name")
        self.msquery.add_filter(ProgramFilter, name=name)

    def compliance_check_status_filter_form_valid(self, form):
        compliance_check = form.cleaned_data.get("compliance_check")
        self.msquery.add_filter(ComplianceCheckStatusFilter, compliance_check_pk=compliance_check.pk)

    def post(self, request, *args, **kwargs):
        try:
            self.object = self.get_object(**kwargs)
        except ObjectDoesNotExist:
            raise Http404
        self.msquery = self.get_msquery(request)
        forms = self.get_forms()
        filter_key = request.POST.get("filter_key")
        form = forms[filter_key]
        if form.is_valid():
            getattr(self, f"{filter_key}_valid")(form)
            return HttpResponseRedirect(self.msquery.get_url())
        return self.form_invalid(**forms)


class IndexView(MachineListView):
    permission_required = "inventory.view_machinesnapshot"

    def get_breadcrumbs(self, **kwargs):
        return [(None, "Inventory machines")]


class GroupsView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.view_machinegroup"
    template_name = "inventory/group_list.html"

    def get(self, request, *args, **kwargs):
        self.search_form = MachineGroupSearchForm(request.GET)
        return super(GroupsView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(GroupsView, self).get_context_data(**kwargs)
        qs = MachineGroup.objects.current()
        if self.search_form.is_valid():
            name = self.search_form.cleaned_data['name']
            if name:
                qs = qs.filter(name__icontains=name)
            source = self.search_form.cleaned_data['source']
            if source:
                qs = qs.filter(source=source)
        context['object_list'] = qs
        context['search_form'] = self.search_form
        breadcrumbs = []
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            breadcrumbs.append((reverse('inventory:groups'), 'Inventory groups'))
            breadcrumbs.append((None, "Search"))
        else:
            breadcrumbs.append((None, "Inventory groups"))
        context['breadcrumbs'] = breadcrumbs
        return context


class GroupMachinesView(MachineListView):
    permission_required = ("inventory.view_machinegroup", "inventory.view_machinesnapshot")

    def get_object(self, **kwargs):
        return MachineGroup.objects.select_related('source').get(pk=kwargs['group_id'])

    def get_msquery(self, request):
        ms_query = super().get_msquery(request)
        ms_query.force_filter(MachineGroupFilter, hidden_value=self.object.pk)
        return ms_query

    def get_list_title(self):
        return "Group: {} - {}".format(self.object.source.name, self.object.name)

    def get_breadcrumbs(self, **kwargs):
        return [(reverse('inventory:groups'), 'Inventory groups'),
                (None, self.object.name)]


class MBUView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "inventory.view_metabusinessunit"
    template_name = "inventory/mbu_list.html"
    paginate_by = 25

    def get(self, request, *args, **kwargs):
        self.search_form = MetaBusinessUnitSearchForm(request.GET)
        return super(MBUView, self).get(request, *args, **kwargs)

    def get_queryset(self, **kwargs):
        qs = MetaBusinessUnit.objects.all()
        if self.search_form.is_valid():
            name = self.search_form.cleaned_data['name']
            if name:
                qs = qs.filter(name__icontains=name)
            source = self.search_form.cleaned_data['source']
            if source:
                qs = qs.filter(businessunit__source=source)
            tag = self.search_form.cleaned_data['tag']
            if tag:
                qs = qs.filter(metabusinessunittag__tag=tag)
        return qs

    def get_context_data(self, **kwargs):
        context = super(MBUView, self).get_context_data(**kwargs)
        context['form'] = self.search_form
        # pagination
        page = context['page_obj']
        # breadcrumbs
        breadcrumbs = []
        qd = self.request.GET.copy()
        qd.pop('page', None)
        reset_link = "?{}".format(qd.urlencode())
        if self.search_form.is_valid() and len([i for i in self.search_form.cleaned_data.values() if i]):
            breadcrumbs.append((reverse('inventory:mbu'), 'Inventory business units'))
            breadcrumbs.append((reset_link, "Search"))
        else:
            breadcrumbs.append((reset_link, "Inventory business units"))
        breadcrumbs.append((None, "page {} of {}".format(page.number, page.paginator.num_pages)))
        context['breadcrumbs'] = breadcrumbs
        return context


class ReviewMBUMergeView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.change_metabusinessunit"
    template_name = "inventory/review_mbu_merge.html"

    def get_context_data(self, **kwargs):
        ctx = super(ReviewMBUMergeView, self).get_context_data(**kwargs)
        ctx['meta_business_units'] = MetaBusinessUnit.objects.filter(id__in=self.request.GET.getlist('mbu_id'))
        return ctx


class MergeMBUView(PermissionRequiredMixin, FormView):
    permission_required = "inventory.change_metabusinessunit"
    template_name = "inventory/merge_mbu.html"
    form_class = MergeMBUForm

    def form_valid(self, form):
        self.dest_mbu = form.merge()
        return super(MergeMBUView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:mbu_machines', args=(self.dest_mbu.id,))


class CreateMBUView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "inventory.add_metabusinessunit"
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    form_class = MetaBusinessUnitForm


class UpdateMBUView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "inventory.change_metabusinessunit"
    template_name = "inventory/edit_mbu.html"
    model = MetaBusinessUnit
    form_class = MetaBusinessUnitForm


class DeleteMBUView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "inventory.delete_metabusinessunit"
    model = MetaBusinessUnit
    success_url = reverse_lazy("inventory:mbu")


class MBUTagsView(PermissionRequiredMixin, FormView):
    permission_required = (
        "inventory.view_metabusinessunittag",
        "inventory.add_metabusinessunittag",
        "inventory.change_metabusinessunittag",
        "inventory.delete_metabusinessunittag",
        "inventory.add_tag",
    )
    template_name = "inventory/mbu_tags.html"
    form_class = AddMBUTagForm

    def dispatch(self, request, *args, **kwargs):
        self.mbu = get_object_or_404(MetaBusinessUnit, pk=kwargs['pk'])
        return super(MBUTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MBUTagsView, self).get_context_data(**kwargs)
        context['meta_business_unit'] = self.mbu
        context['tags'] = self.mbu.tags()
        context['color_presets'] = TAG_COLOR_PRESETS
        return context

    def get_form_kwargs(self, *args, **kwargs):
        kwargs = super(MBUTagsView, self).get_form_kwargs(*args, **kwargs)
        kwargs['meta_business_unit'] = self.mbu
        return kwargs

    def form_valid(self, form):
        form.save()
        return super(MBUTagsView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:mbu_tags', args=(self.mbu.id,))


class RemoveMBUTagView(PermissionRequiredMixin, View):
    permission_required = "inventory.delete_metabusinessunittag"

    def post(self, request, *args, **kwargs):
        MetaBusinessUnitTag.objects.filter(tag__id=kwargs['tag_id'],
                                           meta_business_unit__id=kwargs['pk']).delete()
        return HttpResponseRedirect(reverse('inventory:mbu_tags', args=(kwargs['pk'],)))


class DetachBUView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.change_businessunit"
    template_name = "inventory/detach_bu.html"

    def dispatch(self, request, *args, **kwargs):
        self.bu = get_object_or_404(BusinessUnit,
                                    pk=kwargs['bu_id'],
                                    meta_business_unit__id=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['bu'] = self.bu
        context['mbu'] = self.bu.meta_business_unit
        return context

    def post(self, *args, **kwargs):
        mbu = self.bu.detach()
        return HttpResponseRedirect(mbu.get_absolute_url())


class MBUMachinesView(MachineListView):
    permission_required = ("inventory.view_metabusinessunit", "inventory.view_machinesnapshot")
    template_name = "inventory/mbu_machines.html"

    def get_object(self, **kwargs):
        return MetaBusinessUnit.objects.get(pk=kwargs['pk'])

    def get_msquery(self, request):
        ms_query = super().get_msquery(request)
        ms_query.force_filter(MetaBusinessUnitFilter, hidden_value=self.object.pk)
        return ms_query

    def get_list_title(self):
        return "BU: {}".format(self.object.name)

    def get_breadcrumbs(self, **kwargs):
        return [(reverse('inventory:mbu'), 'Inventory business units'),
                (None, self.object.name)]


class MachineHeartbeatsView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.view_machinesnapshot"
    template_name = "inventory/_machine_heartbeats.html"
    time_range_days = 15  # TODO hard coded

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["machine"] = machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        prepared_heartbeats = []
        try:
            last_machine_heartbeats = stores.admin_console_store.get_last_machine_heartbeats(
                machine.serial_number,
                from_dt=datetime.utcnow() - timedelta(days=self.time_range_days)
            )
        except Exception:
            logger.exception("Could not get machine heartbeats")
        else:
            for event_class, source_name, ua_max_dates in last_machine_heartbeats:
                heartbeat_timeout = event_class.get_machine_heartbeat_timeout(machine.serial_number)
                if heartbeat_timeout:
                    heartbeat_timeout = timedelta(seconds=heartbeat_timeout)
                ua_max_dates.sort(key=lambda t: (t[1], t[0]), reverse=True)
                date_class = None
                if ua_max_dates:
                    # should always be the case
                    all_ua_max_date = ua_max_dates[0][1]
                    if timezone.is_aware(all_ua_max_date):
                        all_ua_max_date = timezone.make_naive(all_ua_max_date)
                    if heartbeat_timeout:
                        if datetime.utcnow() - all_ua_max_date > heartbeat_timeout:
                            date_class = "danger"
                        else:
                            date_class = "success"
                prepared_heartbeats.append(
                    (event_class.get_event_type_display(),
                     source_name, ua_max_dates, date_class)
                )
            prepared_heartbeats.sort()
        ctx["heartbeats"] = prepared_heartbeats
        ctx["time_range_days"] = self.time_range_days
        return ctx


class MachineView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.view_machinesnapshot"
    template_name = "inventory/machine_detail.html"

    def get_context_data(self, **kwargs):
        context = super(MachineView, self).get_context_data(**kwargs)
        context['machine'] = machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['serial_number'] = machine.serial_number

        # machine snapshots
        context['machine_snapshots'] = []

        try:
            tab_order = [str(s).lower() for s in settings["apps"]["zentral.contrib.inventory"].get("tab_order", [])]
        except Exception:
            tab_order = []

        def ms_sort_key(t):
            source_display_name, source, _ = t
            try:
                tab_idx = tab_order.index(source.name.lower())
            except ValueError:
                tab_idx = 999
            return (tab_idx, source_display_name.lower())

        for source_display, source, ms in sorted(((ms.source.get_display_name(), ms.source, ms)
                                                  for ms in machine.snapshots),
                                                 key=ms_sort_key):
            source_subview = _get_source_machine_subview(source, machine.serial_number, self.request.user)
            context['machine_snapshots'].append((source_display, ms, source_subview))

        # heartbeats?
        context['fetch_heartbeats'] = stores.admin_console_store.last_machine_heartbeats

        # compliance checks
        compliance_check_statuses = []
        cc_total = cc_ok = cc_pending = cc_unknown = cc_failed = 0
        if self.request.user.has_perm("compliance_checks.view_machinestatus"):
            for cc_model, cc_pk, cc_name, status, status_time in machine.compliance_check_statuses():
                cc_url = None
                cc_cls = compliance_check_class_from_model(cc_model)
                if self.request.user.has_perms(cc_cls.required_view_permissions):
                    cc_url = reverse("compliance_checks:redirect", args=(cc_pk,))
                compliance_check_statuses.append((cc_url, cc_name, status, status_time))
                cc_total += 1
                if status == Status.OK:
                    cc_ok += 1
                elif status == Status.PENDING:
                    cc_pending += 1
                elif status == Status.UNKNOWN:
                    cc_unknown += 1
                elif status == Status.FAILED:
                    cc_failed += 1
        context["compliance_check_statuses"] = compliance_check_statuses
        context["compliance_check_total"] = cc_total
        context["compliance_check_ok"] = cc_ok
        context["compliance_check_failed"] = cc_failed
        context["compliance_check_pending"] = cc_pending
        context["compliance_check_unknown"] = cc_unknown

        # event links
        context['show_events_link'] = stores.admin_console_store.machine_events
        store_links = []
        for store in stores.iter_events_url_store_for_user("machine", self.request.user):
            url = "{}?{}".format(
                reverse("inventory:machine_events_store_redirect",
                        args=(machine.get_urlsafe_serial_number(),)),
                urlencode({"es": store.name,
                           "tr": MachineEventsView.default_time_range})
            )
            store_links.append((url, store.name))
        context["store_links"] = store_links

        # other actions
        context["actions"] = _get_machine_actions(machine.serial_number, self.request.user)

        return context


class ArchiveMachineView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.change_machinesnapshot"
    template_name = "inventory/archive_machine.html"

    def dispatch(self, request, *args, **kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs['urlsafe_serial_number'])
        return super(ArchiveMachineView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(ArchiveMachineView, self).get_context_data(**kwargs)
        context['machine'] = self.machine
        return context

    def post(self, request, *args, **kwargs):
        self.machine.archive()
        return redirect('inventory:index')


class MachineEventsMixin:
    permission_required = ("inventory.view_machinesnapshot",)
    store_method_scope = "machine"

    def get_object(self, **kwargs):
        return MetaMachine.from_urlsafe_serial_number(kwargs['urlsafe_serial_number'])

    def get_fetch_kwargs_extra(self):
        return {"serial_number": self.object.serial_number}

    def get_fetch_url(self):
        return reverse('inventory:fetch_machine_events', args=(self.object.get_urlsafe_serial_number(),))

    def get_redirect_url(self):
        return reverse('inventory:machine_events', args=(self.object.get_urlsafe_serial_number(),))

    def get_store_redirect_url(self):
        return reverse('inventory:machine_events_store_redirect', args=(self.object.get_urlsafe_serial_number(),))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["machine"] = self.object
        ctx["serial_number"] = self.object.serial_number
        return ctx


class MachineEventsView(MachineEventsMixin, EventsView):
    template_name = "inventory/machine_events.html"


class FetchMachineEventsView(MachineEventsMixin, FetchEventsView):
    include_machine_info = False


class MachineEventsStoreRedirectView(MachineEventsMixin, EventsStoreRedirectView):
    pass


# machine extras


class MachineExtrasView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.view_machinesnapshot"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        self.machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['machine'] = self.machine
        context['serial_number'] = self.machine.serial_number
        return context


class MachineAndroidAppsView(MachineExtrasView):
    template_name = "inventory/machine_android_apps.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        tabs = []
        base_link_url = reverse("inventory:index")
        for ms in self.machine.snapshots_with_android_apps():
            rows = []
            for android_app in ms.ordered_android_apps():
                if android_app.display_name:
                    ms_query = MSQuery()
                    ms_query.force_filter(SourceFilter, value=ms.source_id)
                    ms_query.force_filter(
                        AndroidAppFilter, display_name=android_app.display_name
                    )
                    app_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                    ms_query.force_filter(
                        AndroidAppFilter, display_name=android_app.display_name, value=android_app.pk
                    )
                    version_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                else:
                    app_link = version_link = None
                rows.append((android_app, app_link, version_link))
            tabs.append((ms, rows))
        ctx["tabs"] = tabs
        return ctx


class MachineDebPackagesView(MachineExtrasView):
    template_name = "inventory/machine_deb_packages.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        tabs = []
        base_link_url = reverse("inventory:index")
        for ms in self.machine.snapshots_with_deb_packages():
            rows = []
            for deb_package in ms.ordered_deb_packages():
                if deb_package.name:
                    ms_query = MSQuery()
                    ms_query.force_filter(SourceFilter, value=ms.source_id)
                    ms_query.force_filter(DebPackageFilter, name=deb_package.name)
                    package_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                    ms_query.force_filter(DebPackageFilter, name=deb_package.name, value=deb_package.pk)
                    version_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                else:
                    package_link = version_link = None
                rows.append((deb_package, package_link, version_link))
            tabs.append((ms, rows))
        ctx["tabs"] = tabs
        return ctx


class MachineIOSAppsView(MachineExtrasView):
    template_name = "inventory/machine_ios_apps.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        tabs = []
        base_link_url = reverse("inventory:index")
        for ms in self.machine.snapshots_with_ios_apps():
            rows = []
            for ios_app in ms.ordered_ios_apps():
                if ios_app.name:
                    ms_query = MSQuery()
                    ms_query.force_filter(SourceFilter, value=ms.source_id)
                    ms_query.force_filter(IOSAppFilter, name=ios_app.name)
                    app_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                    ms_query.force_filter(IOSAppFilter, name=ios_app.name, value=ios_app.pk)
                    version_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                else:
                    app_link = version_link = None
                rows.append((ios_app, app_link, version_link))
            tabs.append((ms, rows))
        ctx["tabs"] = tabs
        return ctx


class MachineMacOSAppInstancesView(MachineExtrasView):
    template_name = "inventory/machine_macos_app_instances.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        tabs = []
        base_link_url = reverse("inventory:index")
        for ms in self.machine.snapshots_with_osx_app_instances():
            rows = []
            for app_instance in ms.ordered_osx_app_instances():
                app = app_instance.app
                if app.bundle_name or app.bundle_id:
                    ms_query = MSQuery()
                    ms_query.force_filter(SourceFilter, value=ms.source_id)
                    if app.bundle_name:
                        ms_query.force_filter(BundleFilter, bundle_name=app.bundle_name)
                    else:
                        ms_query.force_filter(BundleFilter, bundle_id=app.bundle_id)
                    bundle_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                    if app.bundle_name:
                        ms_query.force_filter(BundleFilter, bundle_name=app.bundle_name, value=app.pk)
                    else:
                        ms_query.force_filter(BundleFilter, bundle_id=app.bundle_id, value=app.pk)
                    version_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                else:
                    bundle_link = version_link = None
                rows.append((app_instance, app, bundle_link, version_link))
            tabs.append((ms, rows))
        ctx["tabs"] = tabs
        return ctx


class MachineProgramInstancesView(MachineExtrasView):
    template_name = "inventory/machine_program_instances.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        tabs = []
        base_link_url = reverse("inventory:index")
        for ms in self.machine.snapshots_with_program_instances():
            rows = []
            for program_instance in ms.ordered_program_instances():
                program = program_instance.program
                if program.name:
                    ms_query = MSQuery()
                    ms_query.force_filter(SourceFilter, value=ms.source_id)
                    ms_query.force_filter(ProgramFilter, name=program.name)
                    program_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                    ms_query.force_filter(ProgramFilter, name=program.name, value=program.pk)
                    version_link = "{}{}".format(base_link_url, ms_query.get_canonical_url())
                else:
                    program_link = version_link = None
                rows.append((program_instance, program, program_link, version_link))
            tabs.append((ms, rows))
        ctx["tabs"] = tabs
        return ctx


class MachineProfilesView(MachineExtrasView):
    template_name = "inventory/machine_profiles.html"


# machine incidents


class MachineIncidentsView(PermissionRequiredMixin, TemplateView):
    permission_required = (
        "inventory.view_machinesnapshot",
        "incidents.view_machineincident"
    )
    template_name = "inventory/machine_incidents.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['machine'] = machine = MetaMachine.from_urlsafe_serial_number(context['urlsafe_serial_number'])
        context['serial_number'] = machine.serial_number
        context['incidents'] = (MachineIncident.objects.select_related("incident")
                                                       .filter(serial_number=machine.serial_number))
        return context


class MachineTagsView(PermissionRequiredMixin, FormView):
    permission_required = (
        "inventory.view_machinetag",
        "inventory.add_machinetag",
        "inventory.change_machinetag",
        "inventory.delete_machinetag",
        "inventory.add_tag",
    )
    template_name = "inventory/machine_tags.html"
    form_class = AddMachineTagForm

    def dispatch(self, request, *args, **kwargs):
        self.machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        self.msn = self.machine.serial_number
        return super(MachineTagsView, self).dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(MachineTagsView, self).get_context_data(**kwargs)
        context['machine'] = self.machine
        context['color_presets'] = TAG_COLOR_PRESETS
        return context

    def get_form_kwargs(self, *args, **kwargs):
        kwargs = super(MachineTagsView, self).get_form_kwargs(*args, **kwargs)
        kwargs['machine_serial_number'] = self.msn
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        form.save()
        return super(MachineTagsView, self).form_valid(form)

    def get_success_url(self):
        return reverse('inventory:machine_tags', args=(self.machine.get_urlsafe_serial_number(),))


class RemoveMachineTagView(PermissionRequiredMixin, View):
    permission_required = "inventory.delete_machinetag"

    def post(self, request, *args, **kwargs):
        tag = get_object_or_404(Tag, pk=kwargs['tag_id'])
        machine = MetaMachine.from_urlsafe_serial_number(kwargs["urlsafe_serial_number"])
        remove_machine_tags(machine.serial_number, [tag], request)
        return HttpResponseRedirect(reverse('inventory:machine_tags', args=(machine.get_urlsafe_serial_number(),)))


# compliance checks


class ComplianceChecksView(PermissionRequiredMixin, ListView):
    permission_required = "inventory.view_jmespathcheck"
    template_name = "inventory/compliancecheck_list.html"
    model = JMESPathCheck


class CreateComplianceCheckView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.add_jmespathcheck"
    template_name = "inventory/compliancecheck_form.html"

    def get_forms(self):
        compliance_check_form_kwargs = {
            "prefix": "ccf",
            "model": InventoryJMESPathCheck.get_model()
        }
        jmespath_check_form_kwargs = {
            "prefix": "jcf"
        }
        # pre-fill fields from devtool
        for field_name in ("source_name", "jmespath_expression"):
            value = self.request.GET.get(field_name)
            if value:
                jmespath_check_form_kwargs.setdefault("initial", {})[field_name] = value
        if self.request.method == "POST":
            compliance_check_form_kwargs["data"] = self.request.POST
            jmespath_check_form_kwargs["data"] = self.request.POST
        return (
            ComplianceCheckForm(**compliance_check_form_kwargs),
            JMESPathCheckForm(**jmespath_check_form_kwargs)
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if "compliance_check_form" not in kwargs and "jmespath_check_form" not in kwargs:
            ctx["compliance_check_form"], ctx["jmespath_check_form"] = self.get_forms()
        return ctx

    def forms_invalid(self, compliance_check_form, jmespath_check_form):
        return self.render_to_response(
            self.get_context_data(compliance_check_form=compliance_check_form,
                                  jmespath_check_form=jmespath_check_form)
        )

    def forms_valid(self, compliance_check_form, jmespath_check_form):
        compliance_check = compliance_check_form.save(commit=False)
        compliance_check.model = InventoryJMESPathCheck.get_model()
        compliance_check.save()
        jmespath_check = jmespath_check_form.save(commit=False)
        jmespath_check.compliance_check = compliance_check
        jmespath_check.save()
        jmespath_check_form.save_m2m()
        event = JMESPathCheckCreated.build_from_request_and_object(self.request, jmespath_check)
        transaction.on_commit(lambda: event.post())
        return redirect(jmespath_check)

    def post(self, request, *args, **kwargs):
        compliance_check_form, jmespath_check_form = self.get_forms()
        if compliance_check_form.is_valid() and jmespath_check_form.is_valid():
            return self.forms_valid(compliance_check_form, jmespath_check_form)
        else:
            return self.forms_invalid(compliance_check_form, jmespath_check_form)


class ComplianceCheckView(PermissionRequiredMixin, DetailView):
    permission_required = "inventory.view_jmespathcheck"
    template_name = "inventory/compliancecheck_detail.html"
    model = JMESPathCheck

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data()
        ctx["compliance_check"] = self.object.compliance_check
        if self.request.user.has_perm("inventory.view_machinesnapshot"):
            ctx["devtool_link"] = "{}?{}".format(
                reverse("inventory:compliance_check_devtool"),
                urlencode({"source_name": self.object.source_name,
                           "jmespath_expression": self.object.jmespath_expression})
            )
        if self.request.user.has_perm(ComplianceCheckEventsMixin.permission_required):
            ctx["show_events_link"] = stores.admin_console_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("inventory:compliance_check_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": ComplianceCheckEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        return ctx


class UpdateComplianceCheckView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.change_jmespathcheck"
    template_name = "inventory/compliancecheck_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.object = get_object_or_404(
            JMESPathCheck.objects.select_related("compliance_check").all(),
            pk=kwargs["pk"]
        )
        self.compliance_check = self.object.compliance_check
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        compliance_check_form_kwargs = {
            "prefix": "ccf",
            "instance": self.compliance_check,
            "model": InventoryJMESPathCheck.get_model()
        }
        jmespath_check_form_kwargs = {
            "prefix": "jcf",
            "instance": self.object,
        }
        if self.request.method == "POST":
            compliance_check_form_kwargs["data"] = self.request.POST
            jmespath_check_form_kwargs["data"] = self.request.POST
        return (
            ComplianceCheckForm(**compliance_check_form_kwargs),
            JMESPathCheckForm(**jmespath_check_form_kwargs)
        )

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if "compliance_check_form" not in kwargs and "jmespath_check_form" not in kwargs:
            ctx["compliance_check_form"], ctx["jmespath_check_form"] = self.get_forms()
        ctx["object"] = self.object
        ctx["compliance_check"] = self.compliance_check
        return ctx

    def forms_invalid(self, compliance_check_form, jmespath_check_form):
        return self.render_to_response(
            self.get_context_data(compliance_check_form=compliance_check_form,
                                  jmespath_check_form=jmespath_check_form)
        )

    def forms_valid(self, compliance_check_form, jmespath_check_form):
        compliance_check = compliance_check_form.save(commit=False)
        compliance_check.model = InventoryJMESPathCheck.get_model()
        if jmespath_check_form.has_changed():
            compliance_check.version = F("version") + 1
        compliance_check.save()
        jmespath_check = jmespath_check_form.save(commit=False)
        jmespath_check.compliance_check = compliance_check
        jmespath_check.save()
        jmespath_check_form.save_m2m()
        if compliance_check_form.has_changed() or jmespath_check_form.has_changed():
            jmespath_check.refresh_from_db()  # get version number
            event = JMESPathCheckUpdated.build_from_request_and_object(self.request, jmespath_check)
            transaction.on_commit(lambda: event.post())
        return redirect(jmespath_check)

    def post(self, request, *args, **kwargs):
        compliance_check_form, jmespath_check_form = self.get_forms()
        if compliance_check_form.is_valid() and jmespath_check_form.is_valid():
            return self.forms_valid(compliance_check_form, jmespath_check_form)
        else:
            return self.forms_invalid(compliance_check_form, jmespath_check_form)


class DeleteComplianceCheckView(PermissionRequiredMixin, DeleteView):
    permission_required = "inventory.delete_jmespathcheck"
    template_name = "inventory/compliancecheck_confirm_delete.html"
    model = JMESPathCheck

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["compliance_check"] = self.object.compliance_check
        return ctx

    def form_valid(self, form):
        name = self.object.compliance_check.name
        event = JMESPathCheckDeleted.build_from_request_and_object(self.request, self.object)
        self.object.compliance_check.delete()
        messages.info(self.request, f'Compliance check "{name}" deleted')
        transaction.on_commit(lambda: event.post())
        return redirect("inventory:compliance_checks")


class ComplianceCheckEventsMixin:
    permission_required = "inventory.view_jmespathcheck"
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(
            JMESPathCheck.objects.select_related("compliance_check").all(),
            pk=kwargs["pk"]
        )

    def get_fetch_kwargs_extra(self):
        return {"key": "inventory_jmespath_check", "val": encode_args((self.object.pk,))}

    def get_fetch_url(self):
        return reverse("inventory:fetch_compliance_check_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("inventory:compliance_check_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("inventory:compliance_check_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["jmespath_check"] = self.object
        ctx["compliance_check"] = self.object.compliance_check
        return ctx


class ComplianceCheckEventsView(ComplianceCheckEventsMixin, EventsView):
    template_name = "inventory/compliancecheck_events.html"


class FetchComplianceCheckEventsView(ComplianceCheckEventsMixin, FetchEventsView):
    pass


class ComplianceCheckEventsStoreRedirectView(ComplianceCheckEventsMixin, EventsStoreRedirectView):
    pass


class ComplianceCheckDevToolView(PermissionRequiredMixin, FormView):
    permission_required = "inventory.view_machinesnapshot"
    template_name = "inventory/compliancecheck_devtool.html"
    form_class = JMESPathCheckDevToolForm

    def render_test(self, form):
        tree = form.cleaned_data.get("tree")
        result = form.cleaned_data.get("result")
        return self.render_to_response(self.get_context_data(form=form, tree=tree, result=result))

    def get_initial(self):
        # pre-fill fields from compliance check
        initial = {}
        source_name = self.request.GET.get("source_name")
        if source_name:
            source = Source.objects.filter(name__iexact=source_name).order_by("pk").first()
            if source:
                initial["source"] = source
        jmespath_expression = self.request.GET.get("jmespath_expression")
        if jmespath_expression:
            initial["jmespath_expression"] = jmespath_expression
        return initial

    def form_invalid(self, form):
        return self.render_test(form)

    def form_valid(self, form):
        if self.request.POST.get("action") == "create":
            return HttpResponseRedirect("{}?{}".format(
                reverse("inventory:create_compliance_check"),
                urlencode({"source_name": form.cleaned_data["source"].name,
                           "jmespath_expression": form.cleaned_data["jmespath_expression"]})
            ))
        else:
            return self.render_test(form)


class ComplianceCheckTerraformExportView(PermissionRequiredMixin, View):
    permission_required = "inventory.view_jmespathcheck"

    def get(self, request, *args, **kwargs):
        return build_config_response(iter_compliance_check_resources(), "terraform_jmespath_checks")


# tags


TAG_COLOR_PRESETS = {
    "green": "61bd4f",
    "yellow": "f2d600",
    "orange": "ffab4a",
    "red": "eb5a46",
    "purple": "c377e0",
    "blue": "0079bf",
    "sky": "00c2e0",
    "lime": "51e898",
    "pink": "ff80ce",
    "black": "4d4d4d",
    "grey": "b6bbbf"
}


class TagsView(PermissionRequiredMixin, TemplateView):
    permission_required = "inventory.view_tag"
    template_name = "inventory/tag_index.html"

    def get_context_data(self, **kwargs):
        ctx = super(TagsView, self).get_context_data(**kwargs)
        ctx['tag_list'] = list(Tag.objects.all())
        ctx['taxonomy_list'] = list(Taxonomy.objects.all())
        return ctx


class CreateTagView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "inventory.add_tag"
    model = Tag
    form_class = CreateTagForm
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['color_presets'] = TAG_COLOR_PRESETS
        return ctx


class UpdateTagView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "inventory.change_tag"
    model = Tag
    form_class = UpdateTagForm
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['color_presets'] = TAG_COLOR_PRESETS
        return ctx


class DeleteTagView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "inventory.delete_tag"
    model = Tag
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super(DeleteTagView, self).get_context_data(**kwargs)
        ctx['links'] = self.object.links()
        return ctx


class CreateTaxonomyView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "inventory.add_taxonomy"
    model = Taxonomy
    fields = ('meta_business_unit', 'name')
    success_url = reverse_lazy("inventory:tags")


class UpdateTaxonomyView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "inventory.change_taxonomy"
    model = Taxonomy
    fields = ('name',)
    success_url = reverse_lazy("inventory:tags")


class DeleteTaxonomyView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "inventory.delete_taxonomy"
    model = Taxonomy
    success_url = reverse_lazy("inventory:tags")

    def get_context_data(self, **kwargs):
        ctx = super(DeleteTaxonomyView, self).get_context_data(**kwargs)
        ctx['links'] = self.object.links()
        return ctx


# Apps


class BaseAppsView(PermissionRequiredMixin, UserPaginationMixin, TemplateView):
    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        if self.request.GET:
            search_form = self.form_class(self.request.GET)
        else:
            search_form = self.form_class()
        ctx['search_form'] = search_form
        ctx["title"] = search_form.title
        qd = self.request.GET.copy()
        try:
            page = int(qd.pop('page', None)[0])
        except (IndexError, TypeError, ValueError):
            page = 1
        if page > 1:
            reset_link = "?{}".format(qd.urlencode())
        else:
            reset_link = "?"
        breadcrumbs = [(reset_link, search_form.title)]
        if search_form.fetch_results():
            (ctx['object_list'],
             ctx['total_objects'],
             previous_page,
             next_page,
             ctx['total_pages']) = search_form.search(page=page, limit=self.get_paginate_by())
            if next_page:
                qd = self.request.GET.copy()
                qd['page'] = next_page
                ctx['next_url'] = "?{}".format(qd.urlencode())
            if previous_page:
                qd = self.request.GET.copy()
                qd['page'] = previous_page
                ctx['previous_url'] = "?{}".format(qd.urlencode())
            breadcrumbs.append((None, "page {} of {}".format(search_form.cleaned_data['page'],
                                                             ctx.get('total_pages', 1))))
            ctx['table_headers'] = search_form.get_table_headers()
        ctx['breadcrumbs'] = breadcrumbs
        return ctx


class AndroidAppsView(BaseAppsView):
    permission_required = "inventory.view_androidapp"
    template_name = "inventory/android_apps.html"
    form_class = AndroidAppSearchForm


class DebPackagesView(BaseAppsView):
    permission_required = "inventory.view_debpackage"
    template_name = "inventory/deb_packages.html"
    form_class = DebPackageSearchForm


class IOSAppsView(BaseAppsView):
    permission_required = "inventory.view_iosapp"
    template_name = "inventory/ios_apps.html"
    form_class = IOSAppSearchForm


class MacOSAppsView(BaseAppsView):
    permission_required = ("inventory.view_osxapp", "inventory.view_osxappinstance")
    template_name = "inventory/macos_apps.html"
    form_class = MacOSAppSearchForm


class ProgramsView(BaseAppsView):
    permission_required = ("inventory.view_program", "inventory.view_programinstance")
    template_name = "inventory/programs.html"
    form_class = ProgramsSearchForm
