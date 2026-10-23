from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from pbac.scoping import visible_rows
from pbac.utils import check_request
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response


# The permissions of a schedule map to no action, so they cannot gate a request here. Each method has
# its own typed decision: the list and the object for the reads, and perform_create, perform_update and
# perform_destroy for the writes, on validated objects and not on primary keys from the request.


class BaseJobScopeList(ListCreateAPIViewWithAudit):
    permission_classes = [IsAuthenticated]
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration", "job")
    create_pbac_request_class = None
    view_pbac_request_class = None

    def filter_queryset(self, queryset):
        return visible_rows(self.request.user, self.view_pbac_request_class, super().filter_queryset(queryset))

    def perform_create(self, serializer):
        # After the validation, so the configuration and the job are instances, not primary keys
        # that can be absent. The DRF permission layer runs first, and has nothing to name.
        pbac_request = self.create_pbac_request_class(self.request.user,
                                                      serializer.validated_data["configuration"],
                                                      serializer.validated_data["job"])
        check_request(self.request, pbac_request)
        super().perform_create(serializer)


class BaseJobScopeDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    permission_classes = [IsAuthenticated]
    view_pbac_request_class = None
    update_pbac_request_class = None
    delete_pbac_request_class = None

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        check_request(request, self.view_pbac_request_class(request.user, instance))
        return Response(self.get_serializer(instance).data)

    def perform_update(self, serializer):
        # The instance, not validated_data. The schedule is the resource, and the serializer
        # already refuses a different configuration or job.
        check_request(self.request, self.update_pbac_request_class(self.request.user, serializer.instance))
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        check_request(self.request, self.delete_pbac_request_class(self.request.user, instance))
        super().perform_destroy(instance)
