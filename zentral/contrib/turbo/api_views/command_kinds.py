from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import FileExport, Sysdiagnose
from ..serializers import FileExportSerializer, SysdiagnoseSerializer
from .base import ScheduledInFilterSet


class CommandKindFilter(ScheduledInFilterSet):
    name = filters.CharFilter()


class BaseCommandKindList(ListCreateAPIViewWithAudit):
    pagination_class = MaxLimitOffsetPagination
    filterset_class = CommandKindFilter


class BaseCommandKindDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError(f"This {instance._meta.verbose_name} cannot be deleted")
        return super().perform_destroy(instance)


class SysdiagnoseList(BaseCommandKindList):
    queryset = Sysdiagnose.objects.select_related("job").order_by("name")
    serializer_class = SysdiagnoseSerializer


class SysdiagnoseDetail(BaseCommandKindDetail):
    queryset = Sysdiagnose.objects.select_related("job").all()
    serializer_class = SysdiagnoseSerializer


class FileExportList(BaseCommandKindList):
    queryset = FileExport.objects.select_related("job").order_by("name")
    serializer_class = FileExportSerializer


class FileExportDetail(BaseCommandKindDetail):
    queryset = FileExport.objects.select_related("job").all()
    serializer_class = FileExportSerializer
