from ..models import RecurringJob
from ..pbac import CreateRecurringJobRequest, DeleteRecurringJobRequest, UpdateRecurringJobRequest
from ..serializers import RecurringJobSerializer
from .base import BaseJobScopeDetail, BaseJobScopeList


class RecurringJobList(BaseJobScopeList):
    queryset = (RecurringJob.objects.select_related("job")
                .prefetch_related("tags", "excluded_tags").order_by("created_at", "pk"))
    serializer_class = RecurringJobSerializer
    create_pbac_request_class = CreateRecurringJobRequest


class RecurringJobDetail(BaseJobScopeDetail):
    queryset = RecurringJob.objects.select_related("job", "configuration").all()
    serializer_class = RecurringJobSerializer
    update_pbac_request_class = UpdateRecurringJobRequest
    delete_pbac_request_class = DeleteRecurringJobRequest
