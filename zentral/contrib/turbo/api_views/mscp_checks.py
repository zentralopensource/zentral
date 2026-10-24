from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import MSCPCheck
from ..serializers import MSCPCheckSerializer
from .base import ScheduledInFilterSet


class MSCPCheckFilter(ScheduledInFilterSet):
    rule_id = filters.CharFilter()
    baseline = filters.CharFilter()


class MSCPCheckList(ListCreateAPIViewWithAudit):
    queryset = MSCPCheck.objects.select_related("job").order_by("rule_id", "baseline", "pk")
    serializer_class = MSCPCheckSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_class = MSCPCheckFilter


class MSCPCheckDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = MSCPCheck.objects.select_related("job").all()
    serializer_class = MSCPCheckSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This mSCP check cannot be deleted")
        return super().perform_destroy(instance)
