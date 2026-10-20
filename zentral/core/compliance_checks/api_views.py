from django.db.models import Count
from django_filters import rest_framework as filters
from rest_framework import generics
from zentral.utils.drf import DefaultDjangoModelPermissions, MaxLimitOffsetPagination
from .models import ComplianceCheck, MachineStatus, Status
from .serializers import ComplianceCheckSerializer, MachineStatusSerializer


def set_status_counts(compliance_checks):
    # a separate query for the checks of the page: with the counts in the list query,
    # Postgres can count the statuses of all the checks before it selects the page
    compliance_checks = {compliance_check.pk: compliance_check for compliance_check in compliance_checks}
    for compliance_check in compliance_checks.values():
        compliance_check.status_counts = {status.name: 0 for status in Status}
        compliance_check.outdated_count = 0
    for compliance_check_pk, version, status, count in (
        MachineStatus.objects.filter(compliance_check__in=list(compliance_checks))
                             .values_list("compliance_check", "compliance_check_version", "status")
                             .annotate(count=Count("pk"))
    ):
        compliance_check = compliance_checks[compliance_check_pk]
        if version == compliance_check.version:
            compliance_check.status_counts[Status(status).name] = count
        else:
            compliance_check.outdated_count += count


class ComplianceCheckList(generics.ListAPIView):
    queryset = ComplianceCheck.objects.order_by("pk")
    serializer_class = ComplianceCheckSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("model", "name")
    pagination_class = MaxLimitOffsetPagination

    def paginate_queryset(self, queryset):
        page = super().paginate_queryset(queryset)
        set_status_counts(page)
        return page


class ComplianceCheckDetail(generics.RetrieveAPIView):
    queryset = ComplianceCheck.objects.all()
    serializer_class = ComplianceCheckSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def get_object(self):
        compliance_check = super().get_object()
        set_status_counts([compliance_check])
        return compliance_check


class MachineStatusList(generics.ListAPIView):
    queryset = MachineStatus.objects.order_by("pk")
    serializer_class = MachineStatusSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("serial_number", "compliance_check_id")
    pagination_class = MaxLimitOffsetPagination
