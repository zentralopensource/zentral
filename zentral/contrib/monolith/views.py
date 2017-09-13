from itertools import chain
import logging
import os.path
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core import signing
from django.core.exceptions import SuspiciousOperation
from django.core.urlresolvers import reverse_lazy
from django.db.models import F
from django.http import (FileResponse,
                         Http404,
                         HttpResponse, HttpResponseForbidden, HttpResponseNotFound, HttpResponseRedirect)
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from zentral.contrib.inventory.models import MetaMachine
from zentral.utils.api_views import (API_SECRET,
                                     APIAuthError, make_secret, verify_secret,
                                     SignedRequestHeaderJSONPostAPIView)
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import monolith_conf
from .events import (post_monolith_cache_server_update_request,
                     post_monolith_munki_request, post_monolith_repository_updates,
                     post_monolith_sync_catalogs_request)
from .forms import (AddManifestCatalogForm, DeleteManifestCatalogForm,
                    AddManifestEnrollmentPackageForm,
                    AddManifestSubManifestForm,
                    CacheServersPostForm,
                    ConfigureCacheServerForm,
                    DeleteManifestSubManifestForm,
                    ManifestForm,
                    PkgInfoSearchForm, UpdatePkgInfoCatalogForm,
                    SubManifestPkgInfoForm, SubManifestAttachmentForm, SubManifestScriptForm)
from .models import (Catalog, CacheServer, Manifest, ManifestEnrollmentPackage, PkgInfo, PkgInfoName,
                     SUB_MANIFEST_PKG_INFO_KEY_CHOICES, SubManifest, SubManifestAttachment, SubManifestPkgInfo)
from .osx_package.builder import MunkiMonolithConfigPkgBuilder
from .utils import build_manifest_enrollment_package

logger = logging.getLogger('zentral.contrib.monolith.views')


class WebHookView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/webhook.html"

    def get_context_data(self, **kwargs):
        context = super(WebHookView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['api_host'] = self.request.get_host()
        context['api_secret'] = make_secret('zentral.contrib.monolith')
        return context


# Pkg infos


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
    form_class = UpdatePkgInfoCatalogForm

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


# Catalogs


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


# Sub Manifests


class SubManifestsView(LoginRequiredMixin, ListView):
    model = SubManifest
    template_name = "monolith/sub_manifest_list.html"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super(SubManifestsView, self).get_context_data(**kwargs)
        context['monolith'] = True
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
    fields = ['name', 'description']
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
        pkg_info_dict = sub_manifest.pkg_info_dict()
        keys = pkg_info_dict.pop("keys")
        sorted_keys = []
        for key, _ in SUB_MANIFEST_PKG_INFO_KEY_CHOICES:
            value = keys.get(key, None)
            if value:
                sorted_keys.append((value['key_display'], value['key_list']))
        context["keys"] = sorted_keys
        context.update(pkg_info_dict)
        context['manifests'] = [(msm.tags.all(), msm.manifest)
                                for msm in sub_manifest.manifestsubmanifest_set.all()]
        return context


class UpdateSubManifestView(LoginRequiredMixin, UpdateView):
    model = SubManifest
    fields = ['name', 'description']
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
        return HttpResponseRedirect(self.get_success_url())

    def get_success_url(self):
        return self.sub_manifest.get_absolute_url()


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
        return self.object.sub_manifest.get_absolute_url()

    def delete(self, request, *args, **kwargs):
        # TODO we can't just use the DeleteView delete method, but can we do better than that ?
        self.object = self.get_object()
        success_url = self.get_success_url()
        SubManifestAttachment.objects.trash(self.object.sub_manifest, self.object.name)
        return HttpResponseRedirect(success_url)


# Manifests


class ManifestsView(LoginRequiredMixin, ListView):
    model = Manifest
    template_name = "monolith/manifest_list.html"
    paginate_by = 10

    def get_context_data(self, **kwargs):
        context = super(ManifestsView, self).get_context_data(**kwargs)
        context['monolith'] = True
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

    def form_valid(self, form):
        response = super().form_valid(form)
        for builder, builder_config in monolith_conf.mandatory_enrollment_package_builders.items():
            mep = ManifestEnrollmentPackage.objects.create(
                manifest=self.object,
                builder=builder,
                build_kwargs=builder_config.get("build_kwargs", {}),
                version=1
            )
            build_manifest_enrollment_package(mep)
        return response


class ManifestView(LoginRequiredMixin, DetailView):
    model = Manifest
    template_name = "monolith/manifest.html"

    def get_context_data(self, **kwargs):
        context = super(ManifestView, self).get_context_data(**kwargs)
        manifest = context["object"]
        context['monolith'] = True
        context['manifest_enrollment_packages'] = list(manifest.manifestenrollmentpackage_set.all())
        context['manifest_enrollment_packages'].sort(key=lambda mep: (mep.get_optional(), mep.get_name(), mep.id))
        context['manifest_cache_servers'] = list(manifest.cacheserver_set.all().order_by("name"))
        context['manifest_catalogs'] = list(manifest.manifestcatalog_set
                                                    .prefetch_related("tags")
                                                    .select_related("catalog").all())
        context['manifest_sub_manifests'] = list(manifest.manifestsubmanifest_set
                                                         .prefetch_related("tags")
                                                         .select_related("sub_manifest").all())
        add_enrollment_package_path = reverse("monolith:add_manifest_enrollment_package", args=(manifest.id,))
        context['add_enrollment_package_links'] = [
            ("{}?builder={}".format(add_enrollment_package_path, k),
             v["class"].name) for k, v in monolith_conf.optional_enrollment_package_builders.items()
        ]
        context['add_enrollment_package_links'].sort(key=lambda t: t[1])
        return context


class ManifestEnrollmentView(LoginRequiredMixin, DetailView):
    model = Manifest
    template_name = "monolith/enrollment.html"

    def get_context_data(self, **kwargs):
        context = super(ManifestEnrollmentView, self).get_context_data(**kwargs)
        context['monolith'] = True
        context['form'] = MunkiMonolithConfigPkgBuilder.form(
            initial={"meta_business_unit": self.object.meta_business_unit}
        )
        return context


class ManifestEnrollmentPkgView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        manifest = get_object_or_404(Manifest, pk=kwargs['pk'])
        form = MunkiMonolithConfigPkgBuilder.form(request.POST)
        if not form.is_valid():
            return HttpResponseRedirect(reverse("monolith:manifest_enrollment"))
        # monolith auth token
        business_unit = manifest.meta_business_unit.api_enrollment_business_units()[0]
        build_kwargs = {"release": form.cleaned_data["release"]}
        builder = MunkiMonolithConfigPkgBuilder(business_unit, **build_kwargs)
        return builder.build_and_make_response()


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


class BaseEditManifestEnrollmentPackageView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/manifest_enrollment_package_forms.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        if "mep_pk" in kwargs:
            print("YO", self.manifest.id, kwargs["mep_pk"])
            self.manifest_enrollment_package = get_object_or_404(ManifestEnrollmentPackage,
                                                                 manifest=self.manifest,
                                                                 pk=kwargs["mep_pk"])
            if not self.manifest_enrollment_package.get_optional():
                raise Http404
            builder = self.manifest_enrollment_package.builder
            self.builder_config = monolith_conf.optional_enrollment_package_builders[builder]
            self.builder_class = self.manifest_enrollment_package.builder_class
        else:
            try:
                self.builder = request.GET["builder"]
                self.builder_config = monolith_conf.optional_enrollment_package_builders[self.builder]
                self.builder_class = self.builder_config["class"]
            except KeyError:
                raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_forms(self):
        builder_form_kwargs = {
            "initial": {"meta_business_unit": self.manifest.meta_business_unit},
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
        elif hasattr(self, "manifest_enrollment_package"):
            builder_form_kwargs["initial"].update(self.manifest_enrollment_package.build_kwargs)
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
        mep = ManifestEnrollmentPackage.objects.create(
            manifest=self.manifest,
            builder=self.builder,
            build_kwargs=builder_form.get_build_kwargs(),
            version=1
        )
        mep.tags = mep_form.cleaned_data["tags"]
        build_manifest_enrollment_package(mep)
        return HttpResponseRedirect(self.manifest.get_absolute_url())


class UpdateManifestEnrollmentPackageView(BaseEditManifestEnrollmentPackageView):
    def forms_valid(self, builder_form, mep_form):
        self.manifest_enrollment_package.build_kwargs = builder_form.get_build_kwargs()
        self.manifest_enrollment_package.tags = mep_form.cleaned_data["tags"]
        self.manifest_enrollment_package.version = F("version") + 1
        self.manifest_enrollment_package.save()
        self.manifest_enrollment_package.refresh_from_db()
        build_manifest_enrollment_package(self.manifest_enrollment_package)
        return HttpResponseRedirect(self.manifest.get_absolute_url())


class DeleteManifestEnrollmentPackageView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/delete_manifest_enrollment_package.html"

    def dispatch(self, request, *args, **kwargs):
        self.manifest_enrollment_package = get_object_or_404(
            ManifestEnrollmentPackage,
            manifest__id=kwargs["pk"], pk=kwargs["mep_pk"]
        )
        if not self.manifest_enrollment_package.get_optional():
            raise Http404
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['manifest_enrollment_package'] = self.manifest_enrollment_package
        context['manifest'] = self.manifest_enrollment_package.manifest
        return context

    def post(self, request, *args, **kwargs):
        redirect_url = self.manifest_enrollment_package.manifest.get_absolute_url()
        self.manifest_enrollment_package.file.delete(save=False)
        self.manifest_enrollment_package.delete()
        return HttpResponseRedirect(redirect_url)


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
            print(form.errors)
            raise SuspiciousOperation("Posted json data invalid")


# managedsoftwareupdate API


class MRBaseView(View):
    def post_monolith_munki_request(self, **payload):
        payload["manifest"] = {"id": self.manifest.id,
                               "name": str(self.manifest)}
        post_monolith_munki_request(self.machine_serial_number, self.user_agent, self.ip, **payload)

    def dispatch(self, request, *args, **kwargs):
        try:
            token = request.META['HTTP_X_MONOLITH_TOKEN'].strip()
            api_data = verify_secret(token, 'zentral.contrib.monolith')
        except (KeyError, ValueError, APIAuthError):
            return HttpResponseForbidden("No no no!")
        self.machine_serial_number = api_data.get("machine_serial_number", None)
        self.user_agent, self.ip = user_agent_and_ip_address_from_request(request)
        self.machine = MetaMachine(self.machine_serial_number)
        self.tags = self.machine.tags
        self.meta_business_unit = api_data['business_unit'].meta_business_unit
        self.manifest = get_object_or_404(Manifest, meta_business_unit=self.meta_business_unit)
        return super().dispatch(request, *args, **kwargs)


class MRSignedView(MRBaseView):
    def get_request_args(self, name):
        try:
            data = signing.loads(name, salt="monolith", key=API_SECRET)
        except signing.BadSignature:
            model = key = None
        else:
            model = data["m"]
            key = data["k"]
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


class MRCatalogView(MRSignedView):
    event_payload_type = "catalog"

    def do_get(self, model, key, event_payload):
        catalog_data = None
        if model == "enrollment_catalog":
            # intercept calls for special enrollment catalog
            mbu_id = int(key)
            if mbu_id == self.meta_business_unit.id:
                catalog_data = self.manifest.serialize_enrollment_catalog(self.tags)
        elif model == "sub_manifest_catalog":
            # intercept calls for sub manifest catalog
            sm_id = int(key)
            event_payload["sub_manifest"] = {"id": sm_id}
            # verify machine access to sub manifest and respond
            sub_manifest = self.manifest.sub_manifest(sm_id, self.tags)
            if sub_manifest:
                catalog_data = sub_manifest.serialize_catalog()
                event_payload["sub_manifest"]["name"] = sub_manifest.name
        elif model == "catalog":
            # intercept calls for manifest catalog
            c_id = int(key)
            event_payload["catalog"] = {"id": c_id}
            # verify machine access to catalog and respond
            catalog = self.manifest.catalog(c_id, self.tags)
            if catalog:
                catalog_data = catalog.serialize()
                event_payload["catalog"].update({"name": catalog.name,
                                                 "priority": catalog.priority})
        if catalog_data:
            return HttpResponse(catalog_data, content_type="application/xml")


class MRManifestView(MRSignedView):
    event_payload_type = "manifest"

    def get_request_args(self, name):
        model, key = super().get_request_args(name)
        if model is None or key is None:
            # No valid signed data.
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


class MRPackageView(MRSignedView):
    event_payload_type = "package"

    def get_request_args(self, name):
        # extension added when building the catalogs
        # so that munki will download it with the right extension as well
        # some tests about the installabiliy of some packages depend on the extension
        signed_payload, _ = os.path.splitext(name)
        return super().get_request_args(signed_payload)

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
                                 self.manifest.enrollment_packages_pkginfo_deps(self.tags)):
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
