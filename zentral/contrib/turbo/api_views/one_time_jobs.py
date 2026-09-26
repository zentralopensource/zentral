from zentral.utils.drf import (DefaultDjangoModelPermissions, ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination, RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import OneTimeJob
from ..pbac import (check_create_one_time_job, check_delete_one_time_job,
                    check_update_one_time_job)
from ..serializers import OneTimeJobSerializer


class OneTimeJobPermissions(DefaultDjangoModelPermissions):
    # turbo.add_onetimejob, change_onetimejob and delete_onetimejob map to no action, so they
    # cannot gate a request here. perform_create, perform_update and perform_destroy authorize
    # the write methods, on validated objects and not on primary keys from the request. GET keeps
    # turbo.view_onetimejob, which is still mapped.
    perms_map = dict(DefaultDjangoModelPermissions.perms_map,
                     POST=[], PUT=[], PATCH=[], DELETE=[])


class OneTimeJobList(ListCreateAPIViewWithAudit):
    permission_classes = [OneTimeJobPermissions]
    queryset = (OneTimeJob.objects.select_related("job")
                .prefetch_related("tags", "excluded_tags").order_by("created_at", "pk"))
    serializer_class = OneTimeJobSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration", "job")

    def perform_create(self, serializer):
        # After the validation, so the configuration and the job are instances, not primary keys
        # that can be absent. The DRF permission layer runs first, and has nothing to name.
        check_create_one_time_job(self.request, serializer.validated_data["configuration"],
                                  serializer.validated_data["job"])
        super().perform_create(serializer)


class OneTimeJobDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    permission_classes = [OneTimeJobPermissions]
    queryset = OneTimeJob.objects.select_related("job", "configuration").all()
    serializer_class = OneTimeJobSerializer

    def perform_update(self, serializer):
        # The instance, not validated_data. The schedule is the resource, and the serializer
        # already refuses a different configuration or job.
        check_update_one_time_job(self.request, serializer.instance)
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        check_delete_one_time_job(self.request, instance)
        super().perform_destroy(instance)
