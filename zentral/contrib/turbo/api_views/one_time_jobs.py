from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import OneTimeJob
from ..serializers import OneTimeJobSerializer


class OneTimeJobList(ListCreateAPIViewWithAudit):
    queryset = OneTimeJob.objects.select_related("job").prefetch_related("tags", "excluded_tags").all()
    serializer_class = OneTimeJobSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration", "job")


class OneTimeJobDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = OneTimeJob.objects.select_related("job").all()
    serializer_class = OneTimeJobSerializer
