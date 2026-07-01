from django.db.models import Q
from django_filters import rest_framework as filters
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Configuration, MSCPCheck
from ..serializers import MSCPCheckSerializer


class MSCPCheckFilter(filters.FilterSet):
    rule_id = filters.CharFilter()
    baseline = filters.CharFilter()
    # the configuration a check runs in is reached through its Job's schedules (recurring or one-time),
    # matching the UI "Scheduled in" search
    configuration = filters.ModelChoiceFilter(queryset=Configuration.objects.all(),
                                              method="filter_configuration")

    def filter_configuration(self, queryset, name, value):
        return queryset.filter(Q(job__recurringjob__configuration=value)
                               | Q(job__onetimejob__configuration=value)).distinct()


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
