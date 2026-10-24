from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Script
from ..serializers import ScriptSerializer
from .base import ScheduledInFilterSet


class ScriptFilter(ScheduledInFilterSet):
    name = filters.CharFilter()


class ScriptList(ListCreateAPIViewWithAudit):
    queryset = Script.objects.select_related("job").order_by("name")
    serializer_class = ScriptSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_class = ScriptFilter


class ScriptDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Script.objects.select_related("job").all()
    serializer_class = ScriptSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This script cannot be deleted")
        return super().perform_destroy(instance)
