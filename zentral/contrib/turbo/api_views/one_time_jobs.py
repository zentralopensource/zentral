from zentral.utils.drf import PBACRetrieveUpdateDestroyAPIViewWithAudit
from ..models import OneTimeJob
from ..pbac import (CreateOneTimeJobRequest, DeleteOneTimeJobRequest, UpdateOneTimeJobRequest,
                    ViewOneTimeJobRequest)
from ..serializers import OneTimeJobSerializer, OneTimeJobUpdateSerializer
from .base import BaseJobScopeList


class OneTimeJobList(BaseJobScopeList):
    queryset = (OneTimeJob.objects.select_related("job")
                .prefetch_related("tags", "excluded_tags").order_by("created_at", "pk"))
    serializer_class = OneTimeJobSerializer
    create_pbac_request_class = CreateOneTimeJobRequest
    view_pbac_request_class = ViewOneTimeJobRequest


class OneTimeJobDetail(PBACRetrieveUpdateDestroyAPIViewWithAudit):
    queryset = OneTimeJob.objects.select_related("job", "configuration").all()
    serializer_class = OneTimeJobUpdateSerializer
    view_pbac_request_class = ViewOneTimeJobRequest
    update_pbac_request_class = UpdateOneTimeJobRequest
    delete_pbac_request_class = DeleteOneTimeJobRequest
