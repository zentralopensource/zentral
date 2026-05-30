import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import FileResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.urls import reverse_lazy
from django.utils.functional import cached_property
from django.views.generic import DetailView, View
from zentral.contrib.mdm.forms import CreatePackageForm, UpdatePackageForm
from zentral.contrib.mdm.models import Package
from zentral.utils.storage import file_storage_has_signed_urls, select_dist_storage
from zentral.utils.views import (CreateViewWithAudit, DeleteViewWithAudit,
                                 UpdateViewWithAudit, UserPaginationListView)


logger = logging.getLogger("zentral.contrib.mdm.views.packages")


class PackageListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "mdm.view_package"
    model = Package


class CreatePackageView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "mdm.add_package"
    model = Package
    form_class = CreatePackageForm
    template_name = "mdm/package_form.html"


class PackageView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_package"
    model = Package


class UpdatePackageView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "mdm.change_package"
    model = Package
    form_class = UpdatePackageForm
    template_name = "mdm/package_update_form.html"


class DeletePackageView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "mdm.delete_package"
    model = Package
    success_url = reverse_lazy("mdm:packages")

    def get_queryset(self):
        return Package.objects.can_be_deleted()


class DownloadPackageView(PermissionRequiredMixin, View):
    permission_required = "mdm.view_package"

    @cached_property
    def _file_storage(self):
        return select_dist_storage()

    @cached_property
    def _redirect_to_files(self):
        return file_storage_has_signed_urls(self._file_storage)

    def get(self, request, **kwargs):
        package = get_object_or_404(Package, pk=kwargs["pk"])
        if self._redirect_to_files:
            return HttpResponseRedirect(self._file_storage.url(package.file.name))
        return FileResponse(
            self._file_storage.open(package.file.name),
            filename=package.filename or f"package_{package.pk}.pkg",
            as_attachment=True,
        )
