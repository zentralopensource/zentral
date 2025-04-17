import logging
from django.contrib.auth.mixins import PermissionRequiredMixin
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


class UpdateEnrollmentCustomViewView(PermissionRequiredMixin, UpdateViewWithAudit):
    permission_required = "mdm.change_enrollmentcustomview"
    model = EnrollmentCustomView
    fields = ("name", "description", "html", "requires_authentication")


class DeleteEnrollmentCustomViewView(PermissionRequiredMixin, DeleteViewWithAudit):
    permission_required = "mdm.delete_enrollmentcustomview"
    success_url = reverse_lazy("mdm:enrollment_custom_views")

    def get_queryset(self):
        return EnrollmentCustomView.objects.can_be_deleted()
