from zentral.utils.drf import PBACRetrieveUpdateDestroyAPIViewWithAudit
from ..models import RecurringJob
from ..pbac import (CreateRecurringJobRequest, DeleteRecurringJobRequest, UpdateRecurringJobRequest,
                    ViewRecurringJobRequest)
from ..serializers import RecurringJobSerializer, RecurringJobUpdateSerializer
from .base import BaseJobScopeList


class RecurringJobList(BaseJobScopeList):
    queryset = (RecurringJob.objects.select_related("job")
                .prefetch_related("tags", "excluded_tags").order_by("created_at", "pk"))
    serializer_class = RecurringJobSerializer
    create_pbac_request_class = CreateRecurringJobRequest
    view_pbac_request_class = ViewRecurringJobRequest


class RecurringJobDetail(PBACRetrieveUpdateDestroyAPIViewWithAudit):
    queryset = RecurringJob.objects.select_related("job", "configuration").all()
    serializer_class = RecurringJobUpdateSerializer
    view_pbac_request_class = ViewRecurringJobRequest
    update_pbac_request_class = UpdateRecurringJobRequest
    delete_pbac_request_class = DeleteRecurringJobRequest
