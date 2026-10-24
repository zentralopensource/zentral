from django_filters import rest_framework as filters
from zentral.utils.drf import ListCreateAPIViewWithAudit, MaxLimitOffsetPagination
from pbac.scoping import visible_rows
from pbac.utils import check_request
from rest_framework.permissions import IsAuthenticated
from ..pbac import scheduled_in
from ..serializers import JobScopeResourceSerializer


class ScheduledInFilterSet(filters.FilterSet):
    # The configuration of a job is reached through its schedules, like the "Scheduled in" search of the
    # console. Only the schedules that the caller can see count, and the id is not loaded: an unknown id gives
    # an empty list.
    configuration = filters.UUIDFilter(method="filter_configuration")

    def filter_configuration(self, queryset, name, value):
        return queryset.filter(scheduled_in(self.request.user, value))


class JobScopeFilter(filters.FilterSet):
    # the ids are not loaded: an unknown id and an id that the caller cannot see give the same empty list
    configuration = filters.UUIDFilter()
    job = filters.UUIDFilter()


class BaseJobScopeList(ListCreateAPIViewWithAudit):
    # The permissions of a schedule map to no action, so they cannot gate a request here. Each method has its
    # own typed decision.
    permission_classes = [IsAuthenticated]
    pagination_class = MaxLimitOffsetPagination
    filterset_class = JobScopeFilter
    create_pbac_request_class = None
    view_pbac_request_class = None

    def filter_queryset(self, queryset):
        return visible_rows(self.request.user, self.view_pbac_request_class, super().filter_queryset(queryset))

    def create(self, request, *args, **kwargs):
        # The errors of the validation tell if a job exists, and if a recurring job of this configuration
        # already runs it. So only the configuration is read first, and a caller who cannot create in it
        # gets a 403 before the validation of the rest. The question has no job, so it is a preview, which
        # PBACPermission refuses: its Deny is final, and perform_create makes the decision.
        serializer = JobScopeResourceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        check_request(request, self.create_pbac_request_class(request.user,
                                                              serializer.validated_data["configuration"]))
        return super().create(request, *args, **kwargs)

    def perform_create(self, serializer):
        # After the validation, so the configuration and the job are instances, not primary keys
        # that can be absent. The DRF permission layer runs first, and has nothing to name.
        pbac_request = self.create_pbac_request_class(self.request.user,
                                                      serializer.validated_data["configuration"],
                                                      serializer.validated_data["job"])
        check_request(self.request, pbac_request)
        super().perform_create(serializer)
