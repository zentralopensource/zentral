import logging
from urllib.parse import urlencode
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.urls import reverse_lazy
from django.http import Http404, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect
from django.template.loader import render_to_string
from django.urls import reverse
from django.views.generic import DetailView, ListView, TemplateView, View
from django.views.generic.edit import CreateView, DeleteView, FormView, UpdateView
from base.notifier import notifier
from zentral.contrib.inventory.forms import EnrollmentSecretForm
from zentral.contrib.inventory.models import EnrollmentSecret, MetaMachine, Tag
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.core.stores.views import EventsView, FetchEventsView, EventsStoreRedirectView
from zentral.utils.terraform import build_config_response
from zentral.utils.text import get_version_sort_key, shard as compute_shard, encode_args
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, UserPaginationListView
from .conf import monolith_conf
from .events import post_monolith_sync_catalogs_request
from .forms import (AddManifestCatalogForm, EditManifestCatalogForm, DeleteManifestCatalogForm,
                    AddManifestEnrollmentPackageForm,
                    AddManifestSubManifestForm, EditManifestSubManifestForm, DeleteManifestSubManifestForm,
                    CatalogForm,
                    EnrollmentForm,
                    ManifestForm, ManifestSearchForm,
                    PackageForm, PkgInfoSearchForm,
                    RepositoryForm,
                    SubManifestForm, SubManifestSearchForm,
                    SubManifestPkgInfoForm)
from .models import (Catalog, CacheServer,
                     EnrolledMachine,
                     Manifest, ManifestEnrollmentPackage, PkgInfo, PkgInfoName,
                     Condition,
                     Repository,
                     SUB_MANIFEST_PKG_INFO_KEY_CHOICES, SubManifest, SubManifestPkgInfo)
from .repository_backends import load_repository_backend, RepositoryBackend
from .repository_backends.azure import AzureRepositoryForm
from .repository_backends.s3 import S3RepositoryForm
from .terraform import iter_resources
from .utils import test_monolith_object_inclusion, test_pkginfo_catalog_inclusion


logger = logging.getLogger('zentral.contrib.monolith.views')


# inventory machine subview


class InventoryMachineSubview:
    template_name = "monolith/_inventory_machine_subview.html"
    source_key = ("zentral.contrib.munki", "Munki")
    err_message = None
    enrolled_machine = None

    def __init__(self, serial_number, user):
        self.user = user
        self.enrolled_machine = (
            EnrolledMachine.objects.select_related("enrollment__manifest")
                                   .filter(serial_number=serial_number)
                                   .order_by("-created_at")
                                   .first()
        )

    def render(self):
        em = self.enrolled_machine
        ctx = {"enrolled_machine": em}
        if em and self.user.has_perms(ManifestMachineInfoView.permission_required):
            manifest = em.enrollment.manifest
            ctx["manifest"] = manifest
            ctx["url"] = (reverse("monolith:manifest_machine_info", args=(manifest.pk,))
                          + "?serial_number=" + em.serial_number)
        return render_to_string(self.template_name, ctx)


# index


class IndexView(LoginRequiredMixin, TemplateView):
    template_name = "monolith/index.html"

    def get_context_data(self, **kwargs):
        if not self.request.user.has_module_perms("monolith"):
            raise PermissionDenied("Not allowed")
        ctx = super().get_context_data(**kwargs)
        ctx["show_terraform_export"] = all(
            self.request.user.has_perm(perm)
            for perm in TerraformExportView.permission_required
        )
        return ctx


# repositories


class RepositoriesView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_repository"
    model = Repository


class CreateRepositoryView(PermissionRequiredMixin, TemplateView):
    template_name = "monolith/repository_form.html"
    permission_required = "monolith.add_repository"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        form = kwargs.get("form")
        if not form:
            form = RepositoryForm(prefix="r")
        context["form"] = form
        azure_form = kwargs.get("azure_form")
        if not azure_form:
            azure_form = AzureRepositoryForm(prefix="azure")
        context["azure_form"] = azure_form
        s3_form = kwargs.get("s3_form")
        if not s3_form:
            s3_form = S3RepositoryForm(prefix="s3")
        context["s3_form"] = s3_form
        return context

    def post(self, request, *args, **kwargs):
        form = RepositoryForm(request.POST, prefix="r")
        azure_form = AzureRepositoryForm(request.POST, prefix="azure")
        s3_form = S3RepositoryForm(request.POST, prefix="s3")
        if form.is_valid():
            backend = RepositoryBackend(form.cleaned_data["backend"])
            backend_form = None
            if backend == RepositoryBackend.AZURE:
                backend_form = azure_form
            elif backend == RepositoryBackend.S3:
                backend_form = s3_form
            if backend_form is None or backend_form.is_valid():
                repository = form.save(commit=False)
                repository.set_backend_kwargs({} if backend_form is None else backend_form.get_backend_kwargs())
                repository.save()

                def post_event_and_notify():
                    event = AuditEvent.build_from_request_and_instance(
                        self.request, repository,
                        action=AuditEvent.Action.CREATED,
                    )
                    event.post()
                    notifier.send_notification("monolith.repository", str(repository.pk))

                transaction.on_commit(post_event_and_notify)
                return redirect(repository)
        return self.render_to_response(
            self.get_context_data(form=form, azure_form=azure_form, s3_form=s3_form)
        )


class RepositoryView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_repository"
    model = Repository

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["catalogs"] = list(self.object.catalog_set.all())
        return ctx


class UpdateRepositoryView(PermissionRequiredMixin, TemplateView):
    template_name = "monolith/repository_form.html"
    permission_required = "monolith.change_repository"

    def dispatch(self, request, *args, **kwargs):
        self.repository = get_object_or_404(Repository.objects.for_update(), pk=kwargs["pk"])
        self.backend = RepositoryBackend(self.repository.backend)
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["object"] = self.repository
        form = kwargs.get("form")
        if not form:
            form = RepositoryForm(prefix="r", instance=self.repository)
        context["form"] = form
        azure_form = kwargs.get("azure_form")
        if not azure_form:
            azure_form = AzureRepositoryForm(
                prefix="azure",
                initial=(
                    self.repository.get_backend_kwargs()
                    if self.backend == RepositoryBackend.AZURE
                    else None
                )
            )
        context["azure_form"] = azure_form
        s3_form = kwargs.get("s3_form")
        if not s3_form:
            s3_form = S3RepositoryForm(
                prefix="s3",
                initial=(
                    self.repository.get_backend_kwargs()
                    if self.backend == RepositoryBackend.S3
                    else None
                )
            )
        context["s3_form"] = s3_form
        return context

    def post(self, request, *args, **kwargs):
        prev_value = self.repository.serialize_for_event()  # before it is updated by the form
        form = RepositoryForm(
            request.POST,
            prefix="r",
            instance=self.repository
        )
        azure_form = AzureRepositoryForm(
            request.POST,
            prefix="azure",
            initial=(
                self.repository.get_backend_kwargs()
                if self.backend == RepositoryBackend.AZURE
                else None
            )
        )
        s3_form = S3RepositoryForm(
            request.POST,
            prefix="s3",
            initial=(
                self.repository.get_backend_kwargs()
                if self.backend == RepositoryBackend.S3
                else None
            )
        )
        if form.is_valid():
            backend = RepositoryBackend(form.cleaned_data["backend"])
            backend_form = None
            if backend == RepositoryBackend.AZURE:
                backend_form = azure_form
            elif backend == RepositoryBackend.S3:
                backend_form = s3_form
            if backend_form is None or backend_form.is_valid():
                repository = form.save(commit=False)
                repository.set_backend_kwargs({} if backend_form is None else backend_form.get_backend_kwargs())
                repository.save()
                for manifest in repository.manifests():
                    manifest.bump_version()

                def post_event_and_notify():
                    event = AuditEvent.build_from_request_and_instance(
                        self.request, repository,
                        action=AuditEvent.Action.UPDATED,
                        prev_value=prev_value
                    )
                    event.post()
                    notifier.send_notification("monolith.repository", str(repository.pk))

                transaction.on_commit(post_event_and_notify)
                return redirect(repository)
        return self.render_to_response(
            self.get_context_data(form=form, azure_form=azure_form, s3_form=s3_form)
        )


class DeleteRepositoryView(PermissionRequiredMixin, DeleteView):
    permission_required = "monolith.delete_repository"
    success_url = reverse_lazy("monolith:repositories")

    def get_queryset(self):
        return Repository.objects.for_deletion()

    def form_valid(self, form):
        self.object = self.get_object()
        # build the event before the object is deleted
        event = AuditEvent.build_from_request_and_instance(
            self.request, self.object,
            action=AuditEvent.Action.DELETED,
            prev_value=self.object.serialize_for_event()
        )
        object_pk = str(self.object.pk)

        def post_event_and_notify():
            event.post()
            notifier.send_notification("monolith.repository", object_pk)

        transaction.on_commit(post_event_and_notify)
        return super().form_valid(form)


class SyncRepositoryView(PermissionRequiredMixin, View):
    permission_required = "monolith.sync_repository"
    success_url = reverse_lazy("monolith:repositories")

    def post(self, request, *args, **kwargs):
        db_repository = get_object_or_404(Repository, pk=kwargs["pk"])
        post_monolith_sync_catalogs_request(request, db_repository)
        repository = load_repository_backend(db_repository)
        try:
            repository.sync_catalogs(request)
        except Exception as e:
            logger.exception("Could not sync repository %s", db_repository.pk)
            messages.error(request, f"Could not sync repository: {e}")
        else:
            messages.info(request, "Repository synced")

            def notify():
                notifier.send_notification("monolith.repository", str(db_repository.pk))

            transaction.on_commit(notify)
        return redirect(db_repository)


# pkg infos


class PkgInfosView(PermissionRequiredMixin, TemplateView):
    permission_required = "monolith.view_pkginfo"
    template_name = "monolith/pkginfo_list.html"

    def get_context_data(self, **kwargs):
        ctx = super(PkgInfosView, self).get_context_data(**kwargs)
        form = PkgInfoSearchForm(self.request.GET)
        form.is_valid()
        ctx['form'] = form
        ctx['name_number'], ctx['info_number'], ctx['pkg_names'] = PkgInfo.objects.alles(
            include_empty_names=True,
            **form.cleaned_data
        )
        if not form.is_initial():
            bc = [(reverse("monolith:pkg_infos"), "PkgInfos"),
                  (None, "Search")]
        else:
            bc = [(None, "PkgInfos")]
        ctx["breadcrumbs"] = bc
        return ctx


class UploadPackageView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_pkginfo"
    template_name = "monolith/package_form.html"
    form_class = PackageForm

    def dispatch(self, request, *args, **kwargs):
        self.pkg_info_name = None
        pin_id = request.GET.get("pin_id")
        if pin_id:
            self.pkg_info_name = get_object_or_404(PkgInfoName, pk=pin_id)
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["pkg_info_name"] = self.pkg_info_name
        return kwargs

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["pkg_info_name"] = self.pkg_info_name
        return ctx


class UpdatePackageView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "monolith.change_pkginfo"
    queryset = PkgInfo.objects.local()
    template_name = "monolith/package_form.html"
    form_class = PackageForm


class UpdatePkgInfoCatalogView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "monolith.change_pkginfo"
    model = PkgInfo
    fields = ['catalogs']


class DeletePkgInfoView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "monolith.delete_pkginfo"
    queryset = PkgInfo.objects.local()

    def get_success_url(self):
        return reverse("monolith:pkg_info_name", args=(self.object.name.pk,))


class CreatePkgInfoNameView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_pkginfoname"
    model = PkgInfoName
    fields = ("name",)

    def get_success_url(self):
        return reverse("monolith:pkg_info", args=(self.object.pk,))


class PkgInfoNameView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_pkginfoname"
    model = PkgInfoName
    template_name = "monolith/pkg_info_name.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        pkg_info_name = ctx["object"]
        # events
        if self.request.user.has_perms(("monolith.view_pkginfo", "monolith.view_pkginfoname")):
            ctx["show_events_link"] = stores.admin_console_store.object_events
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
        ctx["object"] = self.object
        return ctx


class PkgInfoNameEventsView(EventsMixin, EventsView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")
    template_name = "monolith/pkg_info_name_events.html"


class FetchPkgInfoNameEventsView(EventsMixin, FetchEventsView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")


class PkgInfoNameEventsStoreRedirectView(EventsMixin, EventsStoreRedirectView):
    permission_required = ("monolith.view_pkginfo", "monolith.view_pkginfoname")


class DeletePkgInfoNameView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "monolith.delete_pkginfoname"
    model = PkgInfoName
    queryset = PkgInfoName.objects.for_deletion()
    success_url = reverse_lazy("monolith:pkg_infos")


# catalogs


class CatalogsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_catalog"
    model = Catalog


class CatalogView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_catalog"
    model = Catalog

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        catalog = ctx["object"]
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


class CreateCatalogView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_catalog"
    model = Catalog
    form_class = CatalogForm


class UpdateCatalogView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "monolith.change_catalog"
    form_class = CatalogForm

    def get_queryset(self):
        return Catalog.objects.for_update()


class DeleteCatalogView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "monolith.delete_catalog"
    queryset = Catalog.objects.for_deletion()
    success_url = reverse_lazy("monolith:catalogs")


# conditions


class ConditionsView(PermissionRequiredMixin, ListView):
    permission_required = "monolith.view_condition"
    model = Condition


class CreateConditionView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_condition"
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = "Create condition"
        return context


class ConditionView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_condition"
    model = Condition

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        condition = context["object"]
        pkg_infos = []
        for smp in condition.submanifestpkginfo_set.select_related("sub_manifest", "pkg_info_name"):
            pkg_infos.append((smp.sub_manifest, smp.pkg_info_name.name,
                              smp.get_absolute_url(),
                              "repository package", smp.get_key_display()))
        pkg_infos.sort(key=lambda t: (t[0].name, t[1], t[3], t[4]))
        context['pkg_infos'] = pkg_infos
        return context


class UpdateConditionView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "monolith.change_condition"
    model = Condition
    fields = ["name", "predicate"]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['title'] = f"Update condition {self.object}"
        return context

    def form_valid(self, form):
        response = super().form_valid(form)
        for manifest in self.object.manifests():
            manifest.bump_version()
        return response


class DeleteConditionView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "monolith.delete_condition"
    queryset = Condition.objects.for_deletion()
    success_url = reverse_lazy("monolith:conditions")


# sub manifests


class SubManifestsView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "monolith.view_submanifest"
    model = SubManifest
    template_name = "monolith/sub_manifest_list.html"

    def get(self, request, *args, **kwargs):
        self.form = SubManifestSearchForm(request.GET)
        self.form.is_valid()
        return super().get(request, *args, **kwargs)

    def get_queryset(self):
        return self.form.get_queryset()

    def get_context_data(self, **kwargs):
        context = super(SubManifestsView, self).get_context_data(**kwargs)
        context['form'] = self.form
        return context


class CreateSubManifestView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_submanifest"
    model = SubManifest
    form_class = SubManifestForm
    template_name = "monolith/edit_sub_manifest.html"


class SubManifestView(PermissionRequiredMixin, DetailView):
    permission_required = "monolith.view_submanifest"
    model = SubManifest
    template_name = "monolith/sub_manifest.html"

    def get_context_data(self, **kwargs):
        context = super(SubManifestView, self).get_context_data(**kwargs)
        sub_manifest = context['object']
        pkg_info_dict = sub_manifest.pkg_info_dict()
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


class UpdateSubManifestView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "monolith.change_submanifest"
    model = SubManifest
    form_class = SubManifestForm
    template_name = 'monolith/edit_sub_manifest.html'


class DeleteSubManifestView(PermissionRequiredMixin, DeleteViewWithAudit):
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

    def get_success_url(self):
        return self.object.sub_manifest.get_absolute_url()

    def form_valid(self, form):
        sub_manifest = self.object.sub_manifest
        response = super().form_valid(form)
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return response


# manifests


class ManifestsView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "monolith.view_manifest"
    model = Manifest
    template_name = "monolith/manifest_list.html"

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
        context['form'] = self.form
        return context


class TerraformExportView(PermissionRequiredMixin, View):
    permission_required = (
        "monolith.view_catalog",
        "monolith.view_condition",
        "monolith.view_enrollment",
        "monolith.view_manifest",
        "monolith.view_submanifest",
    )

    def get(self, request, *args, **kwargs):
        return build_config_response(iter_resources(), "terraform_monolith")


class CreateManifestView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "monolith.add_manifest"
    model = Manifest
    form_class = ManifestForm


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
                                                    .select_related("catalog")
                                                    .order_by("catalog__repository__name", "catalog__name")
                                                    .all())
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


class UpdateManifestView(PermissionRequiredMixin, UpdateViewWithAudit):
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
        enrolled_machine = EnrolledMachine.objects.filter(
            enrollment__manifest=manifest,
            serial_number=serial_number
        ).order_by("-created_at").first()
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
                    for _, smpi in key_d['key_list']:
                        name = smpi.get_name()
                        shard_repr = default_shard_repr = excluded_tag_names = tag_shards = None
                        options = getattr(smpi, "options", None)
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

            for sub_manifest, smpi_list in sub_manifest_objects.items():
                for name, key, excluded_tag_names, shard_repr, default_shard_repr, tag_shards, included in smpi_list:
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
