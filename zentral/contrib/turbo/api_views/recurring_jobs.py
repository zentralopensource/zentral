from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import RecurringJob
from ..serializers import RecurringJobSerializer


class RecurringJobList(ListCreateAPIViewWithAudit):
    queryset = RecurringJob.objects.select_related("job").prefetch_related("tags", "excluded_tags").all()
    serializer_class = RecurringJobSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration", "job")


class RecurringJobDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = RecurringJob.objects.select_related("job").all()
    serializer_class = RecurringJobSerializer
