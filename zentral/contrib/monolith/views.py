from itertools import chain
import logging
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.cache import cache
from django.core.exceptions import PermissionDenied, SuspiciousOperation
from django.urls import reverse_lazy
from django.http import (FileResponse,
                         Http404,
                         HttpResponse, HttpResponseForbidden, HttpResponseNotFound, HttpResponseRedirect)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import EnrollmentSecret, MachineTag, MetaMachine
from zentral.contrib.inventory.utils import verify_enrollment_secret
from zentral.utils.api_views import make_secret, SignedRequestHeaderJSONPostAPIView
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import monolith_conf
from .events import (post_monolith_cache_server_update_request,
                     post_monolith_enrollment_event,
                     post_monolith_munki_request, post_monolith_repository_updates,
                     post_monolith_sync_catalogs_request)
from .forms import (AddManifestCatalogForm, DeleteManifestCatalogForm,
                    AddManifestEnrollmentPackageForm,
                    AddManifestSubManifestForm,
                    CacheServersPostForm,
                    ConfigureCacheServerForm,
                    DeleteManifestSubManifestForm,
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
from .utils import build_configuration_plist, build_configuration_profile

logger = logging.getLogger('zentral.contrib.monolith.views')


# repository sync configuration


class WebHookView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/webhook.html"

    def get_context_data(self, **kwargs):
        context = super(WebHookView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['api_host'] = self.request.get_host()
        context['api_secret'] = make_secret('zentral.contrib.monolith')
        return context


# pkg infos


class PkgInfosView(LoginRequiredMixin, TemplateView):
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


class UpdatePkgInfoCatalogView(LoginRequiredMixin, UpdateView):
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


class PkgInfoNameView(LoginRequiredMixin, DetailView):
    model = PkgInfoName
    template_name = "monolith/pkg_info_name.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        pkg_info_name = ctx["object"]
        # sub manifests
        sub_manifests = []
        for smpi in pkg_info_name.submanifestpkginfo_set.select_related("sub_manifest").order_by("sub_manifest__name"):
            sub_manifests.append((smpi.sub_manifest, smpi.get_key_display()))
        ctx["sub_manifests"] = sub_manifests
        # pkg infos
        ctx["pkg_infos"] = list(pkg_info_name.pkginfo_set.select_related("name")
                                                         .prefetch_related("catalogs")
                                                         .filter(archived_at__isnull=True))
        # to display update catalog links or not
        ctx["manual_catalog_management"] = monolith_conf.repository.manual_catalog_management
        return ctx


# PPDs


class PPDsView(LoginRequiredMixin, ListView):
    model = PrinterPPD


class UploadPPDView(LoginRequiredMixin, CreateView):
    model = PrinterPPD
    form_class = UploadPPDForm

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["title"] = "Upload PPD file"
        return ctx


class PPDView(LoginRequiredMixin, DetailView):
    model = PrinterPPD

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["printers"] = list(ctx["object"].printer_set.filter(trashed_at__isnull=True))
        return ctx


# catalogs


class CatalogsView(LoginRequiredMixin, ListView):
    model = Catalog

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["manual_catalog_management"] = monolith_conf.repository.manual_catalog_management
        if monolith_conf.repository.manual_catalog_management:
            ctx["edit_catalog_view"] = "monolith:update_catalog"
        else:
            ctx["edit_catalog_view"] = "monolith:update_catalog_priority"
        return ctx


class CatalogView(LoginRequiredMixin, DetailView):
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


class ManualCatalogManagementRequiredMixin(LoginRequiredMixin):
    def dispatch(self, request, *args, **kwargs):
        self.manual_catalog_management = monolith_conf.repository.manual_catalog_management
        if not self.manual_catalog_management:
            return HttpResponseForbidden("Automatic catalog management. "
                                         "See configuration. "
                                         "You can't create catalogs.")
        return super().dispatch(request, *args, **kwargs)


class CreateCatalogView(ManualCatalogManagementRequiredMixin, CreateView):
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
    model = Catalog
    fields = ['name', 'priority']

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Update catalog {}".format(ctx["object"])
        return ctx


class UpdateCatalogPriorityView(LoginRequiredMixin, UpdateCatalogMixin, UpdateView):
    model = Catalog
    fields = ['priority']

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx['title'] = "Update catalog {} priority".format(ctx["object"])
        return ctx


class DeleteCatalogView(LoginRequiredMixin, DeleteView):
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


class ConditionsView(LoginRequiredMixin, ListView):
    model = Condition

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context


class CreateConditionView(LoginRequiredMixin, CreateView):
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        context['title'] = "Create condition"
        return context


class ConditionView(LoginRequiredMixin, DetailView):
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


class UpdateConditionView(LoginRequiredMixin, UpdateView):
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        condition = context["object"]
        context['title'] = "Update condition {}".format(condition.name)
        return context


class DeleteConditionView(LoginRequiredMixin, DeleteView):
    model = Condition
    success_url = reverse_lazy("monolith:conditions")
    # TODO: can_be_deleted?

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context


# sub manifests


class SubManifestsView(LoginRequiredMixin, ListView):
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


class CreateSubManifestView(LoginRequiredMixin, CreateView):
    model = SubManifest
    form_class = SubManifestForm
    template_name = "monolith/edit_sub_manifest.html"

    def get_context_data(self, **kwargs):
        context = super(CreateSubManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class SubManifestView(LoginRequiredMixin, DetailView):
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


class UpdateSubManifestView(LoginRequiredMixin, UpdateView):
    model = SubManifest
    form_class = SubManifestForm
    template_name = 'monolith/edit_sub_manifest.html'

    def get_context_data(self, **kwargs):
        context = super(UpdateSubManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class DeleteSubManifestView(LoginRequiredMixin, DeleteView):
    model = SubManifest
    success_url = reverse_lazy("monolith:sub_manifests")


class SubManifestAddPkgInfoView(LoginRequiredMixin, FormView):
    form_class = SubManifestPkgInfoForm
    template_name = 'monolith/edit_sub_manifest_pkg_info.html'

    def dispatch(self, request, *args, **kwargs):
        self.sub_manifest = SubManifest.objects.get(pk=kwargs['pk'])
        return super(SubManifestAddPkgInfoView, self).dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super(SubManifestAddPkgInfoView, self).get_form_kwargs()
        kwargs['sub_manifest'] = self.sub_manifest
        return kwargs

    def get_context_data(self, **kwargs):
        context = super(SubManifestAddPkgInfoView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['sub_manifest'] = self.sub_manifest
        return context

    def form_valid(self, form):
        smpi = form.save(commit=False)
        smpi.sub_manifest = self.sub_manifest
        smpi.save()
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return self.sub_manifest.get_absolute_url()


class DeleteSubManifestPkgInfoView(LoginRequiredMixin, DeleteView):
    model = SubManifestPkgInfo
    template_name = "monolith/delete_sub_manifest_pkg_info.html"

    def get_context_data(self, **kwargs):
        context = super(DeleteSubManifestPkgInfoView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def get_success_url(self):
        return self.object.sub_manifest.get_absolute_url()


class SubManifestAddAttachmentView(LoginRequiredMixin, FormView):
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
        return HttpResponseRedirect(smpi.get_absolute_url())


class SubManifestAddScriptView(LoginRequiredMixin, FormView):
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
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return self.sub_manifest.get_absolute_url()


class SubManifestUpdateScriptView(LoginRequiredMixin, FormView):
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
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return self.sub_manifest.get_absolute_url()


class DeleteSubManifestAttachmentView(LoginRequiredMixin, DeleteView):
    model = SubManifestAttachment
    template_name = "monolith/delete_sub_manifest_attachment.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def get_success_url(self):
        return self.object.get_absolute_url()

    def delete(self, request, *args, **kwargs):
        # TODO we can't just use the DeleteView delete method, but can we do better than that ?
        self.object = self.get_object()
        success_url = self.get_success_url()
        SubManifestAttachment.objects.trash(self.object.sub_manifest, self.object.name)
        return HttpResponseRedirect(success_url)


class PurgeSubManifestAttachmentView(LoginRequiredMixin, DeleteView):
    model = SubManifestAttachment
    template_name = "monolith/purge_sub_manifest_attachment.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['monolith'] = True
        return context

    def get_success_url(self):
        return self.object.sub_manifest.get_absolute_url()


class DownloadSubManifestAttachmentView(LoginRequiredMixin, View):
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


class ManifestsView(LoginRequiredMixin, ListView):
    model = Manifest
    template_name = "monolith/manifest_list.html"
    paginate_by = 10

    def get(self, request, *args, **kwargs):
        self.form = ManifestSearchForm(request.GET)
        self.form.is_valid()
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


class CreateManifestView(LoginRequiredMixin, CreateView):
    model = Manifest
    form_class = ManifestForm
    template_name = "monolith/edit_manifest.html"

    def get_context_data(self, **kwargs):
        context = super(CreateManifestView, self).get_context_data(**kwargs)
        context['monolith'] = True
        return context


class ManifestView(LoginRequiredMixin, DetailView):
    model = Manifest
    template_name = "monolith/manifest.html"

    def get_context_data(self, **kwargs):
        context = super(ManifestView, self).get_context_data(**kwargs)
        manifest = context["object"]
        context['monolith'] = True
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


class AddManifestEnrollmentView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/enrollment_form.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        secret_form_kwargs = {"prefix": "secret",
                              "meta_business_unit": self.manifest.meta_business_unit,
                              "initial": {"meta_business_unit": self.manifest.meta_business_unit}}
        enrollment_form_kwargs = {"meta_business_unit": self.manifest.meta_business_unit,
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


class ManifestEnrollmentConfigurationProfileView(LoginRequiredMixin, View):
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


# manifest catalogs


class BaseManifestM2MView(LoginRequiredMixin, FormView):
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
        return HttpResponseRedirect(self.get_success_url())


class AddManifestCatalogView(BaseManifestM2MView):
    form_class = AddManifestCatalogForm
    template_name = "monolith/add_manifest_catalog.html"


class DeleteManifestCatalogView(BaseManifestM2MView):
    form_class = DeleteManifestCatalogForm
    template_name = "monolith/delete_manifest_catalog.html"
    m2m_model = Catalog

    def get_initial(self):
        return {'catalog': self.m2m_object}


# manifest enrollment packages


class BaseEditManifestEnrollmentPackageView(LoginRequiredMixin, TemplateView):
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
            "update_for": self.builder_config["update_for"]
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


class AddManifestEnrollmentPackageView(BaseEditManifestEnrollmentPackageView):
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
        enrollment.save()  # bump mep version and build package via callback call
        return HttpResponseRedirect(self.manifest.get_absolute_url())


class UpdateManifestEnrollmentPackageView(BaseEditManifestEnrollmentPackageView):
    def forms_valid(self, builder_form, mep_form):
        self.manifest_enrollment_package.tags.set(mep_form.cleaned_data["tags"])
        self.manifest_enrollment_package.save()
        builder_form.save()  # bump mep version and build package via callback call
        return HttpResponseRedirect(self.manifest.get_absolute_url())


class DeleteManifestEnrollmentPackageView(LoginRequiredMixin, TemplateView):
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
        redirect_url = self.manifest_enrollment_package.manifest.get_absolute_url()
        self.manifest_enrollment_package.delete()
        return HttpResponseRedirect(redirect_url)


# manifest printers


class AddManifestPrinterView(LoginRequiredMixin, CreateView):
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
        return HttpResponseRedirect("{}#printers".format(self.manifest.get_absolute_url()))


class UpdateManifestPrinterView(LoginRequiredMixin, UpdateView):
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

    def get_success_url(self):
        return "{}#printers".format(self.manifest.get_absolute_url())


class DeleteManifestPrinterView(LoginRequiredMixin, DeleteView):
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
        return HttpResponseRedirect("{}#printers".format(self.manifest.get_absolute_url()))


# manifest sub manifests


class AddManifestSubManifestView(BaseManifestM2MView):
    form_class = AddManifestSubManifestForm
    template_name = "monolith/add_manifest_sub_manifest.html"


class DeleteManifestSubManifestView(BaseManifestM2MView):
    form_class = DeleteManifestSubManifestForm
    template_name = "monolith/delete_manifest_sub_manifest.html"
    m2m_model = SubManifest

    def get_initial(self):
        return {'sub_manifest': self.m2m_object}


class ConfigureManifestCacheServerView(LoginRequiredMixin, FormView):
    form_class = ConfigureCacheServerForm
    template_name = "monolith/configure_manifest_cache_server.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["monolith"] = True
        ctx["manifest"] = self.manifest
        return ctx

    def form_valid(self, form):
        ctx = self.get_context_data()
        ctx["curl_command"] = form.build_curl_command(self.manifest)
        return render(self.request, 'monolith/manifest_cache_server_setup.html', ctx)


class DeleteManifestCacheServerView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        cache_server = get_object_or_404(CacheServer, pk=kwargs["cs_pk"], manifest__pk=kwargs["pk"])
        manifest = cache_server.manifest
        cache_server.delete()
        return HttpResponseRedirect("{}#cache-servers".format(manifest.get_absolute_url()))


# API


class SyncCatalogsView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral.contrib.monolith"

    def do_post(self, data):
        post_monolith_sync_catalogs_request(self.user_agent, self.ip)
        monolith_conf.repository.sync_catalogs()
        return {'status': 0}


class CacheServersView(SignedRequestHeaderJSONPostAPIView):
    verify_module = "zentral.contrib.monolith"

    def do_post(self, data):
        form = CacheServersPostForm(data)
        if form.is_valid():
            manifest = get_object_or_404(Manifest, meta_business_unit=self.business_unit.meta_business_unit)
            cache_server = form.save(manifest, self.ip)
            post_monolith_cache_server_update_request(self.user_agent, self.ip, cache_server=cache_server)
            return {'status': 0}
        else:
            post_monolith_cache_server_update_request(self.user_agent, self.ip, errors=form.errors)
            # TODO: JSON response with error code and form.errors.as_json()
            raise SuspiciousOperation("Posted json data invalid")


class DownloadPrinterPPDView(View):
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
            return FileResponse(printer_ppd.file)


# managedsoftwareupdate API


class MRBaseView(View):
    def post_monolith_munki_request(self, **payload):
        payload["manifest"] = {"id": self.manifest.id,
                               "name": str(self.manifest)}
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

    def get_enrolled_machine(self, request):
        secret = self.get_secret(request)
        serial_number = self.get_serial_number(request)
        cache_key = "{}{}".format(secret, serial_number)
        enrolled_machine = cache.get(cache_key)
        if not enrolled_machine:
            try:
                enrolled_machine = (EnrolledMachine.objects.select_related("enrollment__secret",
                                                                           "enrollment__manifest__meta_business_unit")
                                                           .get(enrollment__secret__secret=secret,
                                                                serial_number=serial_number))
            except EnrolledMachine.DoesNotExist:
                enrolled_machine = self.enroll_machine(request, secret, serial_number)
            cache.set(cache_key, enrolled_machine, 600)
        return enrolled_machine

    def dispatch(self, request, *args, **kwargs):
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        enrolled_machine = self.get_enrolled_machine(request)
        self.manifest = enrolled_machine.enrollment.manifest
        self.meta_business_unit = self.manifest.meta_business_unit
        self.machine_serial_number = enrolled_machine.serial_number
        self.machine = MetaMachine(self.machine_serial_number)
        self.tags = self.machine.tags
        return super().dispatch(request, *args, **kwargs)


class MRNameView(MRBaseView):
    def get_request_args(self, name):
        try:
            model, key = parse_munki_name(name)
        except MunkiNameError:
            model = key = None
        return model, key

    def get(self, request, *args, **kwargs):
        event_payload = {"type": self.event_payload_type}
        model, key = self.get_request_args(kwargs["name"])
        if model is None or key is None:
            error = True
            response = HttpResponseForbidden("No no no!")
        else:
            event_payload["subtype"] = model
            response = self.do_get(model, key, event_payload)
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

    def do_get(self, model, key, event_payload):
        catalog_data = None
        if model == "manifest_catalog":
            # intercept calls for special enrollment catalog
            mbu_id = int(key)
            if mbu_id == self.meta_business_unit.id:
                catalog_data = self.manifest.serialize_catalog(self.tags)
        if catalog_data:
            return HttpResponse(catalog_data, content_type="application/xml")


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

    def do_get(self, model, key, event_payload):
        manifest_data = None
        if model == "manifest":
            manifest_data = self.manifest.serialize(self.tags)
        elif model == "sub_manifest":
            sm_id = int(key)
            # verify machine access to sub manifest and respond
            sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
            event_payload["sub_manifest"] = {"id": sm_id}
            if sub_manifest:
                event_payload["sub_manifest"]["name"] = sub_manifest.name
                manifest_data = sub_manifest.serialize()
        if manifest_data:
            return HttpResponse(manifest_data, content_type="application/xml")


class MRPackageView(MRNameView):
    event_payload_type = "package"

    def do_get(self, model, key, event_payload):
        if model == "enrollment_pkg":
            # intercept calls for mbu enrollment packages
            mep_id = int(key)
            event_payload["manifest_enrollment_package"] = {"id": mep_id}
            try:
                mep = ManifestEnrollmentPackage.objects.get(manifest=self.manifest, pk=mep_id)
            except ManifestEnrollmentPackage.DoesNotExist:
                return
            event_payload["manifest_enrollment_package"]["filename"] = mep.file.name
            return FileResponse(mep.file)
        elif model == "sub_manifest_attachment":
            # intercept calls for sub manifest attachments
            # the sma key is sub_manifest, name, version, but we encoded only sub_manifest id and sma id
            # we need to recover the name before we can look for an active version.
            sm_id, sma_id = key
            event_payload["sub_manifest"] = {"id": sm_id}
            event_payload["sub_manifest_attachment"] = {"req_id": sma_id}
            try:
                req_sma = SubManifestAttachment.objects.get(sub_manifest__id=sm_id, pk=sma_id)
            except SubManifestAttachment.DoesNotExist:
                return
            event_payload["sub_manifest_attachment"]["name"] = req_sma.name
            sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
            if sub_manifest:
                event_payload["sub_manifest"]["name"] = sub_manifest.name
                try:
                    sma = SubManifestAttachment.objects.active().get(sub_manifest=sub_manifest,
                                                                     name=req_sma.name)
                except SubManifestAttachment.DoesNotExist:
                    pass
                else:
                    event_payload["sub_manifest_attachment"].update({"id": sma.id,
                                                                     "filename": sma.file.name})
                    return FileResponse(sma.file)
            else:
                return
        elif model == "repository_package":
            pk = int(key)
            event_payload["repository_package"] = {"id": pk}
            # TODO: cache
            for pkginfo in chain(self.manifest.pkginfos_with_deps_and_updates(self.tags),
                                 self.manifest.enrollment_packages_pkginfo_deps(self.tags),
                                 self.manifest.printers_pkginfo_deps(self.tags),
                                 self.manifest.default_managed_installs_deps(self.tags)):
                if pkginfo.pk == pk:
                    event_payload["repository_package"].update({"name": pkginfo.name.name,
                                                                "version": pkginfo.version})
                    cache_server = CacheServer.objects.get_current_for_manifest_and_ip(self.manifest, self.ip)
                    return monolith_conf.repository.make_munki_repository_response(
                        "pkgs", pkginfo.data["installer_item_location"],
                        cache_server=cache_server
                    )


class MRRedirectView(MRBaseView):
    section = None

    def get(self, request, *args, **kwargs):
        name = kwargs["name"]
        self.post_monolith_munki_request(type=self.section, name=name)
        return monolith_conf.repository.make_munki_repository_response(self.section, name)
