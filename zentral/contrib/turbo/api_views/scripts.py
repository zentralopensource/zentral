from django.db.models import Q
from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Configuration, Script
from ..serializers import ScriptSerializer


class ScriptFilter(filters.FilterSet):
    name = filters.CharFilter()
    # the configuration a script runs in is reached through its Job's schedules (recurring or one-time),
    # matching the UI "Scheduled in" search
    configuration = filters.ModelChoiceFilter(queryset=Configuration.objects.all(),
                                              method="filter_configuration")

    def filter_configuration(self, queryset, name, value):
        return queryset.filter(Q(job__recurringjob__configuration=value)
                               | Q(job__onetimejob__configuration=value)).distinct()


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
