from itertools import chain
import logging
import plistlib
import random
from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.core.files.storage import default_storage
from django.db.models import ProtectedError
from django.urls import reverse_lazy
from django.http import (FileResponse,
                         Http404,
                         HttpResponse, HttpResponseForbidden, HttpResponseNotFound, HttpResponseRedirect)
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.functional import cached_property
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import EnrollmentSecret, MachineTag, MetaMachine, Tag
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.core.stores.conf import frontend_store, stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.http import user_agent_and_ip_address_from_request
from zentral.utils.storage import file_storage_has_signed_urls
from zentral.utils.text import get_version_sort_key, shard as compute_shard, encode_args
from .conf import monolith_conf
from .events import (post_monolith_enrollment_event,
                     post_monolith_munki_request, post_monolith_repository_updates)
from .forms import (AddManifestCatalogForm, EditManifestCatalogForm, DeleteManifestCatalogForm,
                    AddManifestEnrollmentPackageForm,
                    AddManifestSubManifestForm, EditManifestSubManifestForm, DeleteManifestSubManifestForm,
                    EnrollmentForm,
                    ManifestForm, ManifestPrinterForm, ManifestSearchForm,
                    PkgInfoSearchForm,
                    SubManifestForm, SubManifestSearchForm,
                    SubManifestPkgInfoForm, SubManifestAttachmentForm, SubManifestScriptForm,
                    UploadPPDForm)
from .models import (MunkiNameError, parse_munki_name,
                     Catalog, CacheServer,
                     EnrolledMachine, Enrollment,
                     Manifest, ManifestEnrollmentPackage, PkgInfo, PkgInfoName,
                     Printer, PrinterPPD,
                     Condition,
                     SUB_MANIFEST_PKG_INFO_KEY_CHOICES, SubManifest, SubManifestAttachment, SubManifestPkgInfo)
from .utils import (build_configuration_plist, build_configuration_profile,
                    filter_catalog_data, filter_sub_manifest_data,
                    test_monolith_object_inclusion, test_pkginfo_catalog_inclusion)


logger = logging.getLogger('zentral.contrib.monolith.views')


# inventory machine subview


class InventoryMachineSubview:
    template_name = "monolith/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.munki", "Munki")
    err_message = None
    enrolled_machine = None

    def __init__(self, serial_number, user):
        self.user = user
        qs = (EnrolledMachine.objects.select_related("enrollment__manifest")
                                     .filter(serial_number=serial_number).order_by("-created_at"))
        count = qs.count()
        if count > 1:
            self.err_message = f"{count} machines found!!!"
        if count > 0:
            self.enrolled_machine = qs.first()

    def render(self):
        em = self.enrolled_machine
        ctx = {"enrolled_machine": em,
               "err_message": self.err_message}
        if em and self.user.has_perms(ManifestMachineInfoView.permission_required):
            manifest = em.enrollment.manifest
            ctx["manifest"] = manifest
            ctx["url"] = (reverse("monolith:manifest_machine_info", args=(manifest.pk,))
                          + "?serial_number=" + em.serial_number)
        return render_to_string(self.template_name, ctx)


# pkg infos


class PkgInfosView(PermissionRequiredMixin, TemplateView):
    permission_required = "monolith.view_pkginfo"
    template_name = "monolith/pkg_info_list.html"

    def get_context_data(self, **kwargs):
        ctx = super(PkgInfosView, self).get_context_data(**kwargs)
        form = PkgInfoSearchForm(self.request.GET)
        form.is_valid()
        ctx['form'] = form
        ctx['name_number'], ctx['info_number'], ctx['pkg_names'] = PkgInfo.objects.alles(**form.cleaned_data)
        if not form.is_initial():
            bc = [(reverse("monolith:pkg_infos"), "Monolith pkg infos"),
                  (None, "Search")]
        else:
            bc = [(None, "Monolith pkg infos")]
        ctx["breadcrumbs"] = bc
        return ctx


class UpdatePkgInfoCatalogView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_pkginfo"
    model = PkgInfo
    fields = ['catalogs']

    def form_valid(self, form):
        old_catalogs = set(self.model.objects.get(pk=self.object.pk).catalogs.all())
        response = super().form_valid(form)
        new_catalogs = set(self.object.catalogs.all())
        if old_catalogs != new_catalogs:
            attr_diff = {}
            removed = old_catalogs - new_catalogs
            if removed:
                attr_diff["removed"] = sorted(str(c) for c in removed)
            added = new_catalogs - old_catalogs
            if added:
                attr_diff["added"] = sorted(str(c) for c in added)
            post_monolith_repository_updates(monolith_conf.repository,
                                             [{"pkg_info": {"name": self.object.name.name,
                                                            "version": self.object.version,
                                                            "diff": {"catalogs": attr_diff}},
                                               "type": "pkg_info",
                                               "action": "updated"}],
                                             self.request)
        return response


class PkgInfoNameView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_pkginfoname"
    model = PkgInfoName
    template_name = "monolith/pkg_info_name.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        pkg_info_name = ctx["object"]
        # events
        if self.request.user.has_perms(("monolith.view_pkginfo", "monolith.view_pkginfoname")):
            ctx["show_events_link"] = frontend_store.object_events
            store_links = []
            for store in stores.iter_events_url_store_for_user("object", self.request.user):
                url = "{}?{}".format(
                    reverse("monolith:pkg_info_name_events_store_redirect", args=(self.object.pk,)),
                    urlencode({"es": store.name,
                               "tr": PkgInfoNameEventsView.default_time_range})
                )
                store_links.append((url, store.name))
            ctx["store_links"] = store_links
        # sub manifests
        sub_manifests = []
        for smpi in pkg_info_name.submanifestpkginfo_set.select_related("sub_manifest").order_by("sub_manifest__name"):
            sub_manifests.append((smpi.sub_manifest, smpi.get_key_display()))
        ctx["sub_manifests"] = sub_manifests
        # pkg infos
        _, _, pkg_name_list = PkgInfo.objects.alles(name_id=pkg_info_name.pk)
        try:
            ctx["pkg_infos"] = pkg_name_list[0]["pkg_infos"]
        except IndexError:
            # should never happen
            logger.error("Could not get pkg infos for name ID %d", pkg_info_name.pk)
            ctx["pkg_infos"] = []
        # to display update catalog links or not
        ctx["manual_catalog_management"] = monolith_conf.repository.manual_catalog_management
        return ctx


class EventsMixin:
    store_method_scope = "object"

    def get_object(self, **kwargs):
        return get_object_or_404(PkgInfoName, pk=kwargs["pk"])

    def get_fetch_kwargs_extra(self):
        return {"key": "munki_pkginfo_name", "val": encode_args((self.object.name,))}

    def get_fetch_url(self):
        return reverse("monolith:fetch_pkg_info_name_events", args=(self.object.pk,))

    def get_redirect_url(self):
        return reverse("monolith:pkg_info_name_events", args=(self.object.pk,))

    def get_store_redirect_url(self):
        return reverse("monolith:pkg_info_name_events_store_redirect", args=(self.object.pk,))

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["monolith"] = True
        ctx["object"] = self.object
        return ctx


class PkgInfoNameEventsView(EventsMixin, EventsView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")
    template_name = "monolith/pkg_info_name_events.html"


class FetchPkgInfoNameEventsView(EventsMixin, FetchEventsView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")


class PkgInfoNameEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")


# PPDs


class PPDsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_printerppd"
    model = PrinterPPD


class UploadPPDView(PermissionRequiredMixin, CreateView):
    permission_required = "monolith.add_printerppd"
    model = PrinterPPD
    form_class = UploadPPDForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Upload PPD file"
        return ctx


class PPDView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_printerppd"
    model = PrinterPPD

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["printers"] = list(ctx["object"].printer_set.filter(trashed_at__isnull=True))
        return ctx


# catalogs


class CatalogsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_catalog"
    model = Catalog

    def get_queryset(self):
        qs = super().get_queryset()
        if not monolith_conf.repository.manual_catalog_management:
            qs = qs.filter(archived_at__isnull=True)
        return qs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["manual_catalog_management"] = monolith_conf.repository.manual_catalog_management
        if monolith_conf.repository.manual_catalog_management:
            ctx["can_create_catalog"] = self.request.user.has_perm("monolith.add_catalog")
        else:
            ctx["can_create_catalog"] = False
        return ctx


class CatalogView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_catalog"
    model = Catalog

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        catalog = ctx["object"]
        # edit view
        if monolith_conf.repository.manual_catalog_management:
            ctx["edit_catalog_view"] = "monolith:update_catalog"
        else:
            ctx["edit_catalog_view"] = "monolith:update_catalog_priority"
        # manifests
        manifests = []
        for mc in (catalog.manifestcatalog_set.select_related("manifest__meta_business_unit")
                                              .prefetch_related("tags")
                                              .all()
                                              .order_by("manifest__meta_business_unit__name")):
            manifests.append((mc.manifest, mc.tags.all()))
        ctx["manifests"] = manifests
        # pkg infos
        ctx["pkg_infos"] = list(catalog.pkginfo_set.filter(archived_at__isnull=True))
        return ctx


class ManualCatalogManagementRequiredMixin(PermissionRequiredMixin):
    def dispatch(self, request, *args, **kwargs):
        self.manual_catalog_management = monolith_conf.repository.manual_catalog_management
        if not self.manual_catalog_management:
            raise PermissionDenied("Automatic catalog management. "
                                   "See configuration. "
                                   "You can't create catalogs.")
        return super().dispatch(request, *args, **kwargs)


class CreateCatalogView(ManualCatalogManagementRequiredMixin, CreateView):
    permission_required = "monolith.add_catalog"
    model = Catalog
    fields = ['name', 'priority']

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Create catalog"
        return ctx

    def form_valid(self, form):
        response = super().form_valid(form)
        post_monolith_repository_updates(monolith_conf.repository,
                                         [{"catalog": {"name": self.object.name,
                                                       "id": self.object.id,
                                                       "priority": self.object.priority},
                                           "type": "catalog",
                                           "action": "added"}],
                                         self.request)
        return response


class UpdateCatalogMixin(object):
    def form_valid(self, form):
        before_object = self.model.objects.get(pk=self.object.pk)
        before = {f: getattr(before_object, f) for f in self.fields}
        response = super().form_valid(form)
        diff = {}
        for f in self.fields:
            before_val = before[f]
            after_val = getattr(self.object, f)
            if after_val != before_val:
                diff[f] = {"removed": before_val,
                           "added": after_val}
        if diff:
            post_monolith_repository_updates(monolith_conf.repository,
                                             [{"catalog": {"name": self.object.name,
                                                           "id": self.object.id,
                                                           "diff": diff},
                                               "type": "catalog",
                                               "action": "updated"}],
                                             self.request)
        return response


class UpdateCatalogView(ManualCatalogManagementRequiredMixin, UpdateCatalogMixin, UpdateView):
    permission_required = "monolith.change_catalog"
    model = Catalog
    fields = ['name', 'priority']

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Update catalog {}".format(ctx["object"])
        return ctx


class UpdateCatalogPriorityView(PermissionRequiredMixin, UpdateCatalogMixin, UpdateView):
    permission_required = "monolith.change_catalog"
    model = Catalog
    fields = ['priority']

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Update catalog {} priority".format(ctx["object"])
        return ctx


class DeleteCatalogView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_catalog"
    model = Catalog
    success_url = reverse_lazy("monolith:catalogs")

    def get_object(self, queryset=None):
        obj = super().get_object(queryset)
        if not obj.can_be_deleted():
            raise Http404("Catalog {} can't be deleted".format(obj))
        return obj

    def delete(self, request, *args, **kwargs):
        response = super().delete(request, *args, **kwargs)
        post_monolith_repository_updates(monolith_conf.repository,
                                         [{"catalog": {"name": self.object.name},
                                           "type": "catalog",
                                           "action": "deleted"}],
                                         request)
        return response


# conditions


class ConditionsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_condition"
    model = Condition

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context


class CreateConditionView(PermissionRequiredMixin, CreateView):
    permission_required = "monolith.add_condition"
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['title'] = "Create condition"
        return context


class ConditionView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_condition"
    model = Condition

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        condition = context["object"]
        pkg_infos = []
        for smp in condition.submanifestpkginfo_set.select_related("sub_manifest", "pkg_info_name"):
            pkg_infos.append((smp.sub_manifest, smp.pkg_info_name.name,
                              smp.get_absolute_url(),
                              "repository package", smp.get_key_display()))
        for sma in condition.submanifestattachment_set.select_related("sub_manifest"):
            pkg_infos.append((sma.sub_manifest, sma.name,
                              sma.get_absolute_url(),
                              sma.get_type_display(), sma.get_key_display()))
        pkg_infos.sort(key=lambda t: (t[0].name, t[1], t[3], t[4]))
        context['pkg_infos'] = pkg_infos
        return context


class UpdateConditionView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_condition"
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        condition = context["object"]
        context['title'] = "Update condition {}".format(condition.name)
        return context

    def form_valid(self, form):
        condition = form.save()
        for manifest in condition.manifests():
            manifest.bump_version()
        return redirect(condition)


class DeleteConditionView(PermissionRequiredMixin, TemplateView):
    permission_required = "monolith.delete_condition"
    template_name = "monolith/condition_confirm_delete.html"

    def dispatch(self, request, *args, **kwargs):
        self.condition = get_object_or_404(Condition, pk=kwargs["pk"])
        if not self.condition.can_be_deleted():
            messages.warning(request, "This condition cannot be deleted")
            return redirect(self.condition)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.condition
        return context

    def post(self, request, *args, **kwargs):
        try:
            self.condition.delete()
        except ProtectedError:
            messages.warning(request, "This condition cannot be deleted")
            return redirect(self.condition)
        else:
            return redirect("monolith:conditions")


# sub manifests


class SubManifestsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_submanifest"
    model = SubManifest
    template_name = "monolith/sub_manifest_list.html"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        self.form = SubManifestSearchForm(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        context = super(SubManifestsView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['form'] = self.form
        # pagination
        page = context['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            context['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            context['previous_url'] = "?{}".format(qd.urlencode())
        return context


class CreateSubManifestView(PermissionRequiredMixin, CreateView):
    permission_required = "monolith.add_submanifest"
    model = SubManifest
    form_class = SubManifestForm
    template_name = "monolith/edit_sub_manifest.html"

    def get_context_data(self, **kwargs):
        context = super(CreateSubManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class SubManifestView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_submanifest"
    model = SubManifest
    template_name = "monolith/sub_manifest.html"

    def get_context_data(self, **kwargs):
        context = super(SubManifestView, self).get_context_data(**kwargs)
        sub_manifest = context['object']
        context['monolith'] = True
        pkg_info_dict = sub_manifest.pkg_info_dict(include_trashed_attachments=True)
        keys = pkg_info_dict.pop("keys")
        sorted_keys = []
        for key, _ in SUB_MANIFEST_PKG_INFO_KEY_CHOICES:
            value = keys.get(key, None)
            if value:
                sorted_keys.append((value['key_display'], value['key_list']))
        context["keys"] = sorted_keys
        context.update(pkg_info_dict)
        context['manifests'] = sub_manifest.manifests_with_tags()
        return context


class UpdateSubManifestView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_submanifest"
    model = SubManifest
    form_class = SubManifestForm
    template_name = 'monolith/edit_sub_manifest.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSubManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class DeleteSubManifestView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_submanifest"
    model = SubManifest
    success_url = reverse_lazy("monolith:sub_manifests")


class SubManifestAddPkgInfoView(PermissionRequiredMixin, FormView):
    permission_required = "monolith.add_submanifestpkginfo"
    form_class = SubManifestPkgInfoForm
    template_name = 'monolith/edit_sub_manifest_pkg_info.html'

    def dispatch(self, request, *args, **kwargs):
        self.sub_manifest = SubManifest.objects.get(pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['sub_manifest'] = self.sub_manifest
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.sub_manifest
        return context

    def form_valid(self, form):
        smpi = form.save(commit=False)
        smpi.sub_manifest = self.sub_manifest
        smpi.save()
        for _, manifest in self.sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(self.sub_manifest)


class UpdateSubManifestPkgInfoView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_submanifestpkginfo"
    model = SubManifestPkgInfo
    form_class = SubManifestPkgInfoForm
    template_name = "monolith/edit_sub_manifest_pkg_info.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.object.sub_manifest
        return context

    def form_valid(self, form):
        smpi = form.save()
        for _, manifest in smpi.sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(smpi.sub_manifest)


class DeleteSubManifestPkgInfoView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_submanifestpkginfo"
    model = SubManifestPkgInfo
    template_name = "monolith/delete_sub_manifest_pkg_info.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def delete(self, *args, **kwargs):
        smpi = self.get_object()
        sub_manifest = smpi.sub_manifest
        smpi.delete()
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(sub_manifest)


class SubManifestAddAttachmentView(PermissionRequiredMixin, FormView):
    permission_required = "monolith.add_submanifestattachment"
    form_class = SubManifestAttachmentForm
    template_name = 'monolith/edit_sub_manifest_attachment.html'

    def dispatch(self, request, *args, **kwargs):
        self.sub_manifest = SubManifest.objects.get(pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['sub_manifest'] = self.sub_manifest
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.sub_manifest
        return context

    def form_valid(self, form):
        smpi = form.save(commit=False)
        smpi.sub_manifest = self.sub_manifest
        smpi.save()
        for _, manifest in self.sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(smpi)


class SubManifestAddScriptView(PermissionRequiredMixin, FormView):
    permission_required = "monolith.add_submanifestattachment"
    form_class = SubManifestScriptForm
    template_name = 'monolith/edit_sub_manifest_script.html'

    def dispatch(self, request, *args, **kwargs):
        self.sub_manifest = SubManifest.objects.get(pk=kwargs['pk'])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['sub_manifest'] = self.sub_manifest
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.sub_manifest
        return context

    def form_valid(self, form):
        smpi = form.save(commit=False)
        smpi.sub_manifest = self.sub_manifest
        smpi.save()
        for _, manifest in self.sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(smpi)


class SubManifestUpdateScriptView(PermissionRequiredMixin, FormView):
    permission_required = "monolith.change_submanifestattachment"
    form_class = SubManifestScriptForm
    template_name = 'monolith/edit_sub_manifest_script.html'

    def dispatch(self, request, *args, **kwargs):
        self.sub_manifest = SubManifest.objects.get(pk=kwargs['sm_pk'])
        self.script = SubManifestAttachment.objects.get(sub_manifest=self.sub_manifest, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['sub_manifest'] = self.sub_manifest
        kwargs['script'] = self.script
        kwargs['initial'] = {'name': self.script.name,
                             'key': self.script.key}
        for attr in ('description', 'installcheck_script',
                     'postinstall_script', 'uninstall_script'):
            kwargs['initial'][attr] = self.script.pkg_info.get(attr, "")
        return kwargs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.sub_manifest
        context['script'] = self.script
        return context

    def form_valid(self, form):
        smpi = form.save(commit=False)
        smpi.sub_manifest = self.sub_manifest
        smpi.save()
        for _, manifest in self.sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(smpi)


class DeleteSubManifestAttachmentView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_submanifestattachment"
    model = SubManifestAttachment
    template_name = "monolith/delete_sub_manifest_attachment.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        sub_manifest = self.object.sub_manifest
        SubManifestAttachment.objects.trash(sub_manifest, self.object.name)
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(self.object)


class PurgeSubManifestAttachmentView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_submanifestattachment"
    model = SubManifestAttachment
    template_name = "monolith/purge_sub_manifest_attachment.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        sub_manifest = self.object.sub_manifest
        self.object.delete()
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return redirect(sub_manifest)


class DownloadSubManifestAttachmentView(PermissionRequiredMixin, View):
    permission_required = "monolith.view_submanifestattachment"

    def get(self, request, *args, **kwargs):
        sma = get_object_or_404(SubManifestAttachment, pk=kwargs["pk"])
        if not sma.can_be_downloaded():
            raise Http404
        response = FileResponse(sma.file)
        content_type = sma.get_content_type()
        if content_type:
            response["Content-Type"] = content_type
        download_name = sma.get_download_name()
        if download_name:
            response["Content-Disposition"] = 'attachment;filename="{}"'.format(download_name)
        return response


# manifests


class ManifestsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_manifest"
    model = Manifest
    template_name = "monolith/manifest_list.html"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        self.form = ManifestSearchForm(request.GET)
        self.form.is_valid()
        if self.form.has_changed() and self.get_queryset().count() == 1:
            return redirect(self.get_queryset().first())
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        context = super(ManifestsView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['form'] = self.form
        # pagination
        page = context['page_obj']
        if page.has_next():
            qd = self.request.GET.copy()
            qd['page'] = page.next_page_number()
            context['next_url'] = "?{}".format(qd.urlencode())
        if page.has_previous():
            qd = self.request.GET.copy()
            qd['page'] = page.previous_page_number()
            context['previous_url'] = "?{}".format(qd.urlencode())
        return context


class CreateManifestView(PermissionRequiredMixin, CreateView):
    permission_required = "monolith.add_manifest"
    model = Manifest
    form_class = ManifestForm

    def get_context_data(self, **kwargs):
        context = super(CreateManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class ManifestView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_manifest"
    model = Manifest
    template_name = "monolith/manifest.html"

    def get_context_data(self, **kwargs):
        context = super(ManifestView, self).get_context_data(**kwargs)
        manifest = context["object"]
        context['enrollments'] = list(manifest.enrollment_set.all())
        context['manifest_enrollment_packages'] = list(manifest.manifestenrollmentpackage_set.all())
        context['manifest_enrollment_packages'].sort(key=lambda mep: (mep.get_name(), mep.id))
        context['manifest_cache_servers'] = list(manifest.cacheserver_set.all().order_by("name"))
        context['manifest_catalogs'] = list(manifest.manifestcatalog_set
                                                    .prefetch_related("tags")
                                                    .select_related("catalog").all())
        context['manifest_printers'] = list(manifest.printer_set
                                                    .prefetch_related("tags")
                                                    .select_related("ppd")
                                                    .filter(trashed_at__isnull=True))
        context['manifest_sub_manifests'] = list(manifest.manifestsubmanifest_set
                                                         .prefetch_related("tags")
                                                         .select_related("sub_manifest").all())
        add_enrollment_package_path = reverse("monolith:add_manifest_enrollment_package", args=(manifest.id,))
        context['add_enrollment_package_links'] = [
            ("{}?builder={}".format(add_enrollment_package_path, k),
             v["class"].name) for k, v in monolith_conf.enrollment_package_builders.items()
        ]
        context['add_enrollment_package_links'].sort(key=lambda t: t[1])
        return context


class UpdateManifestView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_manifest"
    model = Manifest
    form_class = ManifestForm


class AddManifestEnrollmentView(PermissionRequiredMixin, TemplateView):
    permission_required = "monolith.add_enrollment"
    template_name = "monolith/enrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret",
                              "meta_business_unit": self.manifest.meta_business_unit,
                              "initial": {"meta_business_unit": self.manifest.meta_business_unit}}
        enrollment_form_kwargs = {"manifest": self.manifest,
                                  "initial": {"manifest": self.manifest}}
        if self.request.method == "POST":
            secret_form_kwargs["data"] = self.request.POST
            enrollment_form_kwargs["data"] = self.request.POST
        return (EnrollmentSecretForm(**secret_form_kwargs),
                EnrollmentForm(**enrollment_form_kwargs))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context["manifest"] = self.manifest
        if "secret_form" not in kwargs or "enrollment_form" not in kwargs:
            context["secret_form"], context["enrollment_form"] = self.get_forms()
        return context

    def forms_invalid(self, secret_form, enrollment_form):
        return self.render_to_response(self.get_context_data(secret_form=secret_form,
                                                             enrollment_form=enrollment_form))

    def forms_valid(self, secret_form, enrollment_form):
        secret = secret_form.save()
        secret_form.save_m2m()
        enrollment = enrollment_form.save(commit=False)
        enrollment.secret = secret
        enrollment.manifest = self.manifest
        enrollment.save()
        enrollment_form.save_m2m()
        return HttpResponseRedirect(enrollment.get_absolute_url())

    def post(self, request, *args, **kwargs):
        secret_form, enrollment_form = self.get_forms()
        if secret_form.is_valid() and enrollment_form.is_valid():
            return self.forms_valid(secret_form, enrollment_form)
        else:
            return self.forms_invalid(secret_form, enrollment_form)


class ManifestEnrollmentConfigurationProfileView(PermissionRequiredMixin, View):
    permission_required = "monolith.view_enrollment"
    format = None

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"], manifest__pk=kwargs["manifest_pk"])
        if self.format == "plist":
            filename, content = build_configuration_plist(enrollment)
        elif self.format == "configuration_profile":
            filename, content = build_configuration_profile(enrollment)
        else:
            raise ValueError("Unknown configuration format: {}".format(self.format))
        response = HttpResponse(content, "application/x-plist")
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        return response


# manifest machine info


class ManifestMachineInfoView(PermissionRequiredMixin, TemplateView):
    permission_required = ("monolith.view_manifest", "monolith.view_pkginfo")
    template_name = "monolith/machine_info.html"

    def get_context_data(self, **kwargs):
        manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        ctx = super().get_context_data(**kwargs)
        ctx["manifest"] = manifest
        packages = {}
        enrolled_machine = None
        serial_number = self.request.GET.get("serial_number")
        if not isinstance(serial_number, str):
            raise Http404
        try:
            enrolled_machine = EnrolledMachine.objects.get(enrollment__manifest=manifest, serial_number=serial_number)
        except EnrolledMachine.DoesNotExist:
            pass
        if enrolled_machine:
            ctx["enrolled_machine"] = enrolled_machine
            machine = MetaMachine(enrolled_machine.serial_number)
            ctx["machine"] = machine
            tag_names = [t.name for t in machine.tags]
            seen_tag_names = set([])

            # managed installs
            managed_installs = {}
            try:
                from zentral.contrib.munki.models import ManagedInstall
            except Exception:
                pass
            else:
                for managed_install in ManagedInstall.objects.filter(machine_serial_number=machine.serial_number):
                    name = managed_install.name
                    if managed_install.installed_version:
                        key = (name, managed_install.installed_version)
                        if managed_install.reinstall:
                            managed_installs[key] = "reinstalled"
                        else:
                            managed_installs[key] = "installed"
                    if managed_install.failed_version:
                        managed_installs[(name, managed_install.failed_version)] = "failed"

            # catalog
            pkgsinfo = []
            for pkginfo in manifest.build_catalog(machine.tags):
                shard_repr = default_shard_repr = excluded_tag_names = tag_shards = None
                options = pkginfo.get("zentral_monolith")
                if options:
                    excluded_tag_names = options.get("excluded_tags")
                    if excluded_tag_names:
                        seen_tag_names.update(excluded_tag_names)
                    shards = options.get("shards")
                    if shards:
                        modulo = shards.get("modulo", 100)
                        default_shard_repr = "{}/{}".format(shards.get("default", 100), modulo)
                        tag_shards = shards.get("tags")
                        if tag_shards:
                            seen_tag_names.update(tag_shards.keys())
                        # modulo + 1 for display, because modulo N is not included until shard N + 1
                        shard_repr = str(compute_shard(pkginfo["name"] + pkginfo["version"] + machine.serial_number,
                                                       modulo=modulo) + 1)
                pkgsinfo.append(
                    (pkginfo,
                     managed_installs.get((pkginfo["name"], pkginfo["version"])),
                     excluded_tag_names,
                     shard_repr,
                     default_shard_repr,
                     tag_shards,
                     test_pkginfo_catalog_inclusion(pkginfo, machine.serial_number, tag_names))
                )
            pkgsinfo.sort(key=lambda t: get_version_sort_key(t[0]["version"]), reverse=True)

            # sub manifests
            sub_manifest_objects = {}
            for sub_manifest in manifest.sub_manifests(machine.tags):
                for key, key_d in sub_manifest.pkg_info_dict()['keys'].items():
                    for _, smo in key_d['key_list']:
                        name = smo.get_name()
                        shard_repr = default_shard_repr = excluded_tag_names = tag_shards = None
                        options = getattr(smo, "options", None)
                        if options:
                            excluded_tag_names = options.get("excluded_tags")
                            if excluded_tag_names:
                                seen_tag_names.update(excluded_tag_names)
                            shards = options.get("shards")
                            if shards:
                                modulo = shards.get("modulo", 100)
                                default_shard_repr = "{}/{}".format(shards.get("default", 100), modulo)
                                tag_shards = shards.get("tags")
                                if tag_shards:
                                    seen_tag_names.update(tag_shards.keys())
                                # modulo + 1 for display, because modulo N is not included until shard N + 1
                                shard_repr = str(compute_shard(name + machine.serial_number, modulo=modulo) + 1)
                        sub_manifest_objects.setdefault(sub_manifest, []).append(
                            (name,
                             key.replace("_", " "),
                             excluded_tag_names,
                             shard_repr,
                             default_shard_repr,
                             tag_shards,
                             test_monolith_object_inclusion(name, options, machine.serial_number, tag_names))
                        )

            seen_tags = {t.name: t for t in Tag.objects.select_related("taxonomy").filter(name__in=seen_tag_names)}

            for pkginfo, status, excluded_tag_names, shard_repr, default_shard_repr, tag_shards, included in pkgsinfo:
                # rehydrate excluded tags using seen tags
                excluded_tags = []
                if excluded_tag_names:
                    for excluded_tag_name in excluded_tag_names:
                        try:
                            excluded_tags.append(seen_tags[excluded_tag_name])
                        except KeyError:
                            logger.warning("Unknown excluded tag name")
                # rehydrate tag shards using seen tags
                prepared_tag_shards = []
                if tag_shards:
                    for tag_name in sorted(tag_shards.keys()):
                        try:
                            prepared_tag_shards.append((seen_tags[tag_name], tag_shards[tag_name]))
                        except KeyError:
                            logger.warning("Unknown tag shard name")
                # add pkginfo to packages
                package_dict = packages.setdefault(pkginfo["name"], {})
                package_dict.setdefault("pkgsinfo", []).append(
                    (pkginfo, status, excluded_tags, shard_repr, default_shard_repr, prepared_tag_shards, included)
                )

            for sub_manifest, smo_list in sub_manifest_objects.items():
                for name, key, excluded_tag_names, shard_repr, default_shard_repr, tag_shards, included in smo_list:
                    # rehydrate excluded tags using seen tags
                    excluded_tags = []
                    if excluded_tag_names:
                        for excluded_tag_name in excluded_tag_names:
                            try:
                                excluded_tags.append(seen_tags[excluded_tag_name])
                            except KeyError:
                                logger.warning("Unknown excluded tag name")
                    # rehydrate tag shards using seen tags
                    prepared_tag_shards = []
                    if tag_shards:
                        for tag_name in sorted(tag_shards.keys()):
                            try:
                                prepared_tag_shards.append((seen_tags[tag_name], tag_shards[tag_name]))
                            except KeyError:
                                logger.warning("Unknown tag shard name")
                    # add sub manifest to packages
                    package_dict = packages.setdefault(name, {})
                    package_dict.setdefault("sub_manifests", []).append(
                        (sub_manifest,
                         key,
                         excluded_tags,
                         shard_repr,
                         default_shard_repr,
                         prepared_tag_shards,
                         included)
                    )

            # root keys
            manifest_data = manifest.build(machine.tags)
            for key, _ in SUB_MANIFEST_PKG_INFO_KEY_CHOICES:
                for name in manifest_data.get(key, []):
                    packages.setdefault(name, {})["manifest"] = key.replace("_", " ")

        ctx["packages"] = [(name, packages[name]) for name in sorted(packages.keys(), key=lambda n: n.lower())]
        return ctx


# manifest catalogs


class BaseManifestM2MView(FormView):
    m2m_model = None

    def dispatch(self, request, *args, **kwargs):
        self.manifest = Manifest.objects.get(pk=kwargs['pk'])
        if self.m2m_model and 'm2m_pk' in kwargs:
            self.m2m_object = self.m2m_model.objects.get(pk=kwargs['m2m_pk'])
        else:
            self.m2m_object = None
        return super(BaseManifestM2MView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(BaseManifestM2MView, self).get_form_kwargs()
        kwargs['manifest'] = self.manifest
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(BaseManifestM2MView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['manifest'] = self.manifest
        context['m2m_object'] = self.m2m_object
        return context

    def get_success_url(self):
        return self.manifest.get_absolute_url()

    def form_valid(self, form):
        form.save()
        self.manifest.bump_version()
        return HttpResponseRedirect(self.get_success_url())


class AddManifestCatalogView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.add_manifestcatalog"
    form_class = AddManifestCatalogForm
    template_name = "monolith/manifest_catalog_form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Add catalog"
        return ctx


class EditManifestCatalogView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.change_manifestcatalog"
    form_class = EditManifestCatalogForm
    template_name = "monolith/manifest_catalog_form.html"
    m2m_model = Catalog

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["catalog"] = self.m2m_object
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = f"Edit {self.m2m_object} catalog tags"
        return ctx


class DeleteManifestCatalogView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.delete_manifestcatalog"
    form_class = DeleteManifestCatalogForm
    template_name = "monolith/delete_manifest_catalog.html"
    m2m_model = Catalog

    def get_initial(self):
        return {'catalog': self.m2m_object}


# manifest enrollment packages


class BaseEditManifestEnrollmentPackageView(TemplateView):
    template_name = "monolith/manifest_enrollment_package_forms.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        if "mep_pk" in kwargs:
            self.manifest_enrollment_package = get_object_or_404(ManifestEnrollmentPackage,
                                                                 manifest=self.manifest,
                                                                 pk=kwargs["mep_pk"])
            builder = self.manifest_enrollment_package.builder
            self.builder_config = monolith_conf.enrollment_package_builders[builder]
            self.builder_class = self.manifest_enrollment_package.builder_class
        else:
            self.manifest_enrollment_package = None
            try:
                self.builder = request.GET["builder"]
                self.builder_config = monolith_conf.enrollment_package_builders[self.builder]
                self.builder_class = self.builder_config["class"]
            except KeyError:
                raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        builder_form_kwargs = {
            "prefix": "builder",
            "enrollment_only": len(self.builder_config["requires"]) > 0
        }
        mep_form_kwargs = {
            "prefix": "mep",
            "manifest": self.manifest
        }
        if self.request.method == "POST":
            for kwargs in (builder_form_kwargs, mep_form_kwargs):
                kwargs["data"] = self.request.POST
        if self.manifest_enrollment_package:
            builder_form_kwargs["instance"] = self.manifest_enrollment_package.get_enrollment()
            mep_form_kwargs["initial"] = {"tags": self.manifest_enrollment_package.tags.all()}
        return (self.builder_class.form(**builder_form_kwargs),
                AddManifestEnrollmentPackageForm(**mep_form_kwargs))

    def forms_invalid(self, builder_form, mep_form):
        return self.render_to_response(self.get_context_data(builder_form=builder_form,
                                                             mep_form=mep_form))

    def get_context_data(self, **kwargs):
        kwargs["manifest"] = self.manifest
        if hasattr(self, "manifest_enrollment_package"):
            kwargs["manifest_enrollment_package"] = self.manifest_enrollment_package
        kwargs["builder_name"] = self.builder_class.name
        if "builder_form" not in kwargs or "mep_form" not in kwargs:
            kwargs["builder_form"], kwargs["mep_form"] = self.get_forms()
        return super().get_context_data(**kwargs)

    def post(self, request, *args, **kwargs):
        builder_form, mep_form = self.get_forms()
        if builder_form.is_valid() and mep_form.is_valid():
            return self.forms_valid(builder_form, mep_form)
        else:
            return self.forms_invalid(builder_form, mep_form)


class AddManifestEnrollmentPackageView(PermissionRequiredMixin, BaseEditManifestEnrollmentPackageView):
    permission_required = "monolith.add_manifestenrollmentpackage"

    def forms_valid(self, builder_form, mep_form):
        # enrollment secret
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.manifest.meta_business_unit)
        # enrollment
        enrollment = builder_form.save(commit=False)
        enrollment.version = 0  # will be saved one extra time, and start at 1
        enrollment.secret = enrollment_secret
        enrollment.save()
        # manifest enrollment package
        mep = ManifestEnrollmentPackage.objects.create(
            manifest=self.manifest,
            builder=self.builder,
            enrollment_pk=enrollment.pk,
            version=0  # will be updated by the callback call in enrollment.save()
        )
        mep.tags.set(mep_form.cleaned_data["tags"])
        # link from enrollment to manifest enrollment package, for config update propagation
        enrollment.distributor = mep
        enrollment.save()  # bump mep and manifest versions, and build package via callback call
        return redirect(self.manifest)


class UpdateManifestEnrollmentPackageView(PermissionRequiredMixin, BaseEditManifestEnrollmentPackageView):
    permission_required = "monolith.change_manifestenrollmentpackage"

    def forms_valid(self, builder_form, mep_form):
        self.manifest_enrollment_package.tags.set(mep_form.cleaned_data["tags"])
        self.manifest_enrollment_package.save()
        builder_form.save()  # bump mep and manifest versions, and build package via callback call
        return redirect(self.manifest)


class DeleteManifestEnrollmentPackageView(PermissionRequiredMixin, TemplateView):
    permission_required = "monolith.delete_manifestenrollmentpackage"
    template_name = "monolith/delete_manifest_enrollment_package.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest_enrollment_package = get_object_or_404(
            ManifestEnrollmentPackage,
            manifest__id=kwargs["pk"], pk=kwargs["mep_pk"]
        )
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['manifest_enrollment_package'] = self.manifest_enrollment_package
        context['manifest'] = self.manifest_enrollment_package.manifest
        return context

    def post(self, request, *args, **kwargs):
        manifest = self.manifest_enrollment_package.manifest
        self.manifest_enrollment_package.delete()
        manifest.bump_version()
        return redirect(manifest)


# manifest printers


class AddManifestPrinterView(PermissionRequiredMixin, CreateView):
    permission_required = "monolith.add_printer"
    model = Printer
    form_class = ManifestPrinterForm
    template_name = "monolith/manifest_printer_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["m_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["manifest"] = self.manifest
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['manifest'] = self.manifest
        return kwargs

    def form_valid(self, form):
        printer = form.save(commit=False)
        printer.manifest = self.manifest
        printer.save()
        form.save_m2m()
        self.manifest.bump_version()
        return HttpResponseRedirect("{}#printers".format(self.manifest.get_absolute_url()))


class UpdateManifestPrinterView(PermissionRequiredMixin, UpdateView):
    permission_required = "monolith.change_printer"
    model = Printer
    form_class = ManifestPrinterForm
    template_name = "monolith/manifest_printer_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["m_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["manifest"] = self.manifest
        return ctx

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['manifest'] = self.manifest
        return kwargs

    def form_valid(self, *args, **kwargs):
        response = super().form_valid(*args, **kwargs)
        self.manifest.bump_version()
        return response

    def get_success_url(self):
        return "{}#printers".format(self.manifest.get_absolute_url())


class DeleteManifestPrinterView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_printer"
    model = Printer
    template_name = "monolith/delete_manifest_printer.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["m_pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["manifest"] = self.manifest
        return ctx

    def delete(self, request, *args, **kwargs):
        self.object = self.get_object()
        self.object.mark_as_trashed()
        self.manifest.bump_version()
        return HttpResponseRedirect("{}#printers".format(self.manifest.get_absolute_url()))


# manifest sub manifests


class AddManifestSubManifestView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.add_manifestsubmanifest"
    form_class = AddManifestSubManifestForm
    template_name = "monolith/manifest_sub_manifest_form.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Add sub manifest"
        return ctx


class EditManifestSubManifestView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.change_manifestsubmanifest"
    form_class = EditManifestSubManifestForm
    template_name = "monolith/manifest_sub_manifest_form.html"
    m2m_model = SubManifest

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["sub_manifest"] = self.m2m_object
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = f"Edit {self.m2m_object} sub manifest tags"
        return ctx


class DeleteManifestSubManifestView(PermissionRequiredMixin, BaseManifestM2MView):
    permission_required = "monolith.delete_manifestsubmanifest"
    form_class = DeleteManifestSubManifestForm
    template_name = "monolith/delete_manifest_sub_manifest.html"
    m2m_model = SubManifest

    def get_initial(self):
        return {'sub_manifest': self.m2m_object}


class DeleteManifestCacheServerView(PermissionRequiredMixin, View):
    permission_required = "monolith.delete_cacheserver"

    def post(self, request, *args, **kwargs):
        cache_server = get_object_or_404(CacheServer, pk=kwargs["cs_pk"], manifest__pk=kwargs["pk"])
        manifest = cache_server.manifest
        cache_server.delete()
        return HttpResponseRedirect("{}#cache-servers".format(manifest.get_absolute_url()))


# extra


class DownloadPrinterPPDView(View):
    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def get(self, request, *args, **kwargs):
        try:
            printer_ppd = PrinterPPD.objects.get_with_token(kwargs["token"])
        except ValueError:
            logger.error("Invalid token %s", kwargs["token"])
            raise Http404
        except PrinterPPD.DoesNotExist:
            logger.warning("Could not find printer PPD with token %s", kwargs["token"])
            raise Http404
        else:
            if self._redirect_to_files:
                return HttpResponseRedirect(default_storage.url(printer_ppd.file.name))
            else:
                return FileResponse(printer_ppd.file)


# managedsoftwareupdate API


class MRBaseView(View):
    def post_monolith_munki_request(self, **payload):
        payload["manifest"] = {"id": self.manifest.id,
                               "name": str(self.manifest),
                               "version": self.manifest.version}
        post_monolith_munki_request(self.machine_serial_number, self.user_agent, self.ip, **payload)

    def get_secret(self, request):
        try:
            return request.META["HTTP_AUTHORIZATION"].strip().split()[-1]
        except (AttributeError, IndexError, KeyError):
            raise PermissionDenied("Could not read enrollment secret")

    def get_serial_number(self, request):
        try:
            return request.META["HTTP_X_ZENTRAL_SERIAL_NUMBER"].strip()
        except (AttributeError, KeyError):
            raise PermissionDenied("Missing custom serial number header")

    def get_uuid(self, request):
        try:
            return request.META["HTTP_X_ZENTRAL_UUID"].strip()
        except (AttributeError, KeyError):
            raise PermissionDenied("Missing custom UUID header")

    def enroll_machine(self, request, secret, serial_number):
        uuid = self.get_uuid(request)
        try:
            es_request = verify_enrollment_secret(
                "monolith_enrollment", secret,
                self.user_agent, self.ip, serial_number, uuid
            )
        except EnrollmentSecretVerificationFailed:
            raise PermissionDenied("Enrollment secret verification failed")
        enrollment = es_request.enrollment_secret.monolith_enrollment
        # get or create enrolled machine
        enrolled_machine, enrolled_machine_created = EnrolledMachine.objects.get_or_create(
            enrollment=enrollment,
            serial_number=serial_number,
        )
        if enrolled_machine_created:
            # apply enrollment secret tags
            for tag in es_request.enrollment_secret.tags.all():
                MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
            post_monolith_enrollment_event(serial_number, self.user_agent, self.ip, {'action': "enrollment"})
        return enrolled_machine

    def get_enrolled_machine_and_tags(self, request):
        secret = self.get_secret(request)
        serial_number = self.get_serial_number(request)
        cache_key = "{}{}".format(secret, serial_number)
        try:
            enrolled_machine, tags = cache.get(cache_key)
        except TypeError:
            try:
                enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__secret",
                                                                           "enrollment__manifest")
                                                           .get(enrollment__secret__secret=secret,
                                                                serial_number=serial_number))
            except EnrolledMachine.DoesNotExist:
                enrolled_machine = self.enroll_machine(request, secret, serial_number)
            machine = MetaMachine(serial_number)
            tags = machine.tags
            cache.set(cache_key, (enrolled_machine, tags), 600)
        return enrolled_machine, tags

    def dispatch(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        enrolled_machine, self.tags = self.get_enrolled_machine_and_tags(request)
        self.machine_serial_number = enrolled_machine.serial_number
        self.manifest = enrolled_machine.enrollment.manifest
        return super().dispatch(request, *args, **kwargs)


class MRNameView(MRBaseView):
    def get_request_args(self, name):
        try:
            model, key = parse_munki_name(name)
        except MunkiNameError:
            model = key = None
        return model, key

    def get_cache_key(self, model, key):
        items = ["monolith",
                 self.manifest.pk, self.manifest.version]
        items.extend(sorted(t.id for t in self.tags))
        items.append(model)
        if isinstance(key, list):
            items.extend(key)
        else:
            items.append(key)
        return ".".join(str(i) for i in items)

    def get(self, request, *args, **kwargs):
        name = kwargs["name"]
        event_payload = {"type": self.event_payload_type,
                         "name": name}
        model, key = self.get_request_args(name)
        if model is None or key is None:
            error = True
            response = HttpResponseForbidden("No no no!")
        else:
            cache_key = self.get_cache_key(model, key)
            event_payload.update({
                "subtype": model,
                "cache": {
                    "key": cache_key,
                    "hit": False
                }
            })
            response = self.do_get(model, key, cache_key, event_payload)
            if not response:
                error = True
                response = HttpResponseNotFound("Not found!")
            else:
                error = False
        event_payload["error"] = error
        self.post_monolith_munki_request(**event_payload)
        return response


class MRCatalogView(MRNameView):
    event_payload_type = "catalog"

    def do_get(self, model, key, cache_key, event_payload):
        if model == "manifest_catalog" and key == self.manifest.pk:
            catalog_data = cache.get(cache_key)
            if not isinstance(catalog_data, list):
                catalog_data = self.manifest.build_catalog(self.tags)
                cache.set(cache_key, catalog_data, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            return HttpResponse(
                plistlib.dumps(
                    filter_catalog_data(
                        catalog_data,
                        self.machine_serial_number,
                        [t.name for t in self.tags]
                    )
                ),
                content_type="application/xml"
            )


class MRManifestView(MRNameView):
    event_payload_type = "manifest"

    def get_request_args(self, name):
        model, key = super().get_request_args(name)
        if model is None or key is None:
            # Not a valid munki name.
            # It is the first request for the main manifest.
            model = "manifest"
            key = self.manifest.id
        return model, key

    def do_get(self, model, key, cache_key, event_payload):
        manifest_data = None
        if model == "manifest":
            manifest_data = cache.get(cache_key)
            if manifest_data is None:
                manifest_data = self.manifest.serialize(self.tags)
                cache.set(cache_key, manifest_data, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
        elif model == "sub_manifest":
            sm_id = key
            event_payload["sub_manifest"] = {"id": sm_id}
            sub_manifest_name = None
            sub_manifest_data = None
            try:
                sub_manifest_name, sub_manifest_data = cache.get(cache_key)
                if not isinstance(sub_manifest_data, dict):  # TODO remove, needed for sm pkg options migration
                    raise ValueError
            except (TypeError, ValueError):
                # verify machine access to sub manifest and respond
                sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
                if sub_manifest:
                    sub_manifest_name = sub_manifest.name
                    sub_manifest_data = sub_manifest.build()
                # set the cache value, even if sub_manifest_name and sub_manifest_data are None
                cache.set(cache_key, (sub_manifest_name, sub_manifest_data), timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if sub_manifest_name:
                event_payload["sub_manifest"]["name"] = sub_manifest_name
            if sub_manifest_data is not None:
                manifest_data = plistlib.dumps(
                    filter_sub_manifest_data(
                        sub_manifest_data,
                        self.machine_serial_number,
                        [t.name for t in self.tags]
                    )
                )
        if manifest_data:
            return HttpResponse(manifest_data, content_type="application/xml")


class MRPackageView(MRNameView):
    event_payload_type = "package"

    def _get_cache_server(self):
        cache_key = f"monolith.{self.manifest.pk}.cache-servers"
        cache_servers = cache.get(cache_key)
        if cache_servers is None:
            max_age = 10 * 60
            cache_servers = list(CacheServer.objects.get_current_for_manifest(self.manifest, max_age // 2))
            cache.set(cache_key, cache_servers, timeout=max_age // 2)
        if cache_servers:
            try:
                return random.choice([cs for cs in cache_servers if cs.ip == self.ip])
            except IndexError:
                return

    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls()

    def do_get(self, model, key, cache_key, event_payload):
        if model == "enrollment_pkg":
            # intercept calls for mbu enrollment packages
            mep_id = key
            event_payload["manifest_enrollment_package"] = {"id": mep_id}
            filename = cache.get(cache_key)
            if filename is None:
                try:
                    mep = ManifestEnrollmentPackage.objects.get(manifest=self.manifest, pk=mep_id)
                except ManifestEnrollmentPackage.DoesNotExist:
                    pass
                else:
                    filename = mep.file.name
                # set the cache value, even if filename is None
                cache.set(cache_key, filename, timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if filename:
                event_payload["manifest_enrollment_package"]["filename"] = filename
                if self._redirect_to_files:
                    return HttpResponseRedirect(default_storage.url(filename))
                else:
                    return FileResponse(default_storage.open(filename))
        elif model == "sub_manifest_attachment":
            # intercept calls for sub manifest attachments
            # the sma key is sub_manifest, name, version, but we encoded only sub_manifest id and sma id
            # we need to recover the name before we can look for an active version.
            sm_id, sma_id = key
            event_payload["sub_manifest"] = {"id": sm_id}
            event_payload["sub_manifest_attachment"] = {"req_id": sma_id}
            sub_manifest_name = sma = None
            try:
                sub_manifest_name, sma = cache.get(cache_key)
            except TypeError:
                sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
                if sub_manifest:
                    sub_manifest_name = sub_manifest.name
                    try:
                        req_sma = SubManifestAttachment.objects.get(sub_manifest=sub_manifest, pk=sma_id)
                    except SubManifestAttachment.DoesNotExist:
                        pass
                    else:
                        try:
                            sma = SubManifestAttachment.objects.active().get(sub_manifest=sub_manifest,
                                                                             name=req_sma.name)
                        except SubManifestAttachment.DoesNotExist:
                            pass
                # set the cache value, even if sub_manifest_name and sma are None
                cache.set(cache_key, (sub_manifest_name, sma), timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if sub_manifest_name:
                event_payload["sub_manifest"]["name"] = sub_manifest_name
            if sma:
                event_payload["sub_manifest_attachment"].update({
                    "id": sma.id,
                    "name": sma.name,
                    "filename": sma.file.name
                })
                # see https://github.com/django/django/commit/f600e3fad6e92d9fe1ad8b351dc8446415f24345
                if self._redirect_to_files:
                    return HttpResponseRedirect(default_storage.url(sma.file.name))
                else:
                    return FileResponse(default_storage.open(sma.file.name))
        elif model == "repository_package":
            pk = key
            event_payload["repository_package"] = {"id": pk}
            pkginfo_name = pkginfo_version = pkginfo_iil = None
            try:
                pkginfo_name, pkginfo_version, pkginfo_iil = cache.get(cache_key)
            except TypeError:
                for pkginfo in chain(self.manifest.pkginfos_with_deps_and_updates(self.tags),
                                     self.manifest.enrollment_packages_pkginfo_deps(self.tags),
                                     self.manifest.printers_pkginfo_deps(self.tags),
                                     self.manifest.default_managed_installs_deps(self.tags)):
                    if pkginfo.pk == pk:
                        pkginfo_name = pkginfo.name.name
                        pkginfo_version = pkginfo.version
                        pkginfo_iil = pkginfo.data["installer_item_location"]
                        break
                # set the cache value, even if pkginfo_name, pkginfo_version and pkginfo_iil are None
                cache.set(cache_key, (pkginfo_name, pkginfo_version, pkginfo_iil), timeout=None)
            else:
                event_payload["cache"]["hit"] = True
            if pkginfo_name is not None:
                event_payload["repository_package"]["name"] = pkginfo_name
            if pkginfo_version is not None:
                event_payload["repository_package"]["version"] = pkginfo_version
            if pkginfo_iil:
                return monolith_conf.repository.make_munki_repository_response(
                    "pkgs", pkginfo_iil, cache_server=self._get_cache_server()
                )


class MRRedirectView(MRBaseView):
    section = None

    def get(self, request, *args, **kwargs):
        name = kwargs["name"]
        self.post_monolith_munki_request(type=self.section, name=name)
        return monolith_conf.repository.make_munki_repository_response(self.section, name)
