from zentral.utils.drf import (DefaultDjangoModelPermissions, ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination, RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import OneTimeJob
from ..pbac import (check_create_one_time_job, check_delete_one_time_job,
                    check_update_one_time_job)
from ..serializers import OneTimeJobSerializer


class OneTimeJobPermissions(DefaultDjangoModelPermissions):
    # turbo.add_onetimejob, change_onetimejob and delete_onetimejob no longer map to an action, so
    # they cannot gate anything here. The write methods are authorized in perform_create /
    # perform_update / perform_destroy instead, on validated objects rather than primary keys off the
    # wire. GET keeps turbo.view_onetimejob, which is still legacy-mapped.
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
        # after validation, so the configuration and the job are instances rather than primary keys
        # that may not exist. The DRF permission layer runs before that, with nothing to name.
        check_create_one_time_job(self.request, serializer.validated_data["configuration"],
                                  serializer.validated_data["job"])
        super().perform_create(serializer)


class OneTimeJobDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    permission_classes = [OneTimeJobPermissions]
    queryset = OneTimeJob.objects.select_related("job", "configuration").all()
    serializer_class = OneTimeJobSerializer

    def perform_update(self, serializer):
        # the instance, not validated_data: the schedule is the resource, and the serializer has
        # already refused a configuration or a job that differs from the one it carries
        check_update_one_time_job(self.request, serializer.instance)
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        check_delete_one_time_job(self.request, instance)
        super().perform_destroy(instance)
