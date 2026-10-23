from ..models import OneTimeJob
from ..pbac import CreateOneTimeJobRequest, DeleteOneTimeJobRequest, UpdateOneTimeJobRequest
from ..serializers import OneTimeJobSerializer, OneTimeJobUpdateSerializer
from .base import BaseJobScopeDetail, BaseJobScopeList


class OneTimeJobList(BaseJobScopeList):
    queryset = (OneTimeJob.objects.select_related("job")
                .prefetch_related("tags", "excluded_tags").order_by("created_at", "pk"))
    serializer_class = OneTimeJobSerializer
    create_pbac_request_class = CreateOneTimeJobRequest


class OneTimeJobDetail(BaseJobScopeDetail):
    queryset = OneTimeJob.objects.select_related("job", "configuration").all()
    serializer_class = OneTimeJobUpdateSerializer
    update_pbac_request_class = UpdateOneTimeJobRequest
    delete_pbac_request_class = DeleteOneTimeJobRequest
