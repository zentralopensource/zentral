import logging
from io import BytesIO
from django.contrib.auth.mixins import PermissionRequiredMixin
from django.http import FileResponse
from django.urls import reverse_lazy
from django.views.generic import DetailView
from zentral.contrib.mdm.models import EnrollmentCustomView
from zentral.utils.views import CreateViewWithAudit, DeleteViewWithAudit, UpdateViewWithAudit, UserPaginationListView


logger = logging.getLogger('zentral.contrib.mdm.views.enrollment_custom_views')


class EnrollmentCustomViewListView(PermissionRequiredMixin, UserPaginationListView):
    permission_required = "mdm.view_enrollmentcustomview"
    model = EnrollmentCustomView

    def get_queryset(self):
        return super().get_queryset().order_by("name")


class CreateEnrollmentCustomViewView(PermissionRequiredMixin, CreateViewWithAudit):
    permission_required = "mdm.add_enrollmentcustomview"
    model = EnrollmentCustomView
    fields = ("name", "description", "html", "requires_authentication")


class EnrollmentCustomViewView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_enrollmentcustomview"
    model = EnrollmentCustomView


class EnrollmentCustomViewDownloadView(PermissionRequiredMixin, DetailView):
    permission_required = "mdm.view_enrollmentcustomview"
    model = EnrollmentCustomView

    def get(self, request, *args, **kwargs):
        self.object = self.get_object()
        html = self.object.html.encode("utf-8")
        buffer = BytesIO(html)
        file_name = f"enrollment_custom_view_{self.object.pk}.html"
        return FileResponse(
            buffer,
            as_attachment=True,
            filename=file_name,
            content_type="text/html; charset=utf-8",
        )


class UpdateEnrollmentCustomViewView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "mdm.change_enrollmentcustomview"
    model = EnrollmentCustomView
    fields = ("name", "description", "html", "requires_authentication")


class DeleteEnrollmentCustomViewView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "mdm.delete_enrollmentcustomview"
    success_url = reverse_lazy("mdm:enrollment_custom_views")

    def get_queryset(self):
        return EnrollmentCustomView.objects.can_be_deleted()
