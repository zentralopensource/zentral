from zentral.utils.drf import (DefaultDjangoModelPermissions, ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination, RetrieveUpdateDestroyAPIViewWithAudit)
from pbac.utils import check_request


class JobScopePermissions(DefaultDjangoModelPermissions):
    # The add, change and delete permissions of a schedule map to no action, so they cannot gate a
    # request here. perform_create, perform_update and perform_destroy authorize the write methods,
    # on validated objects and not on primary keys from the request. GET keeps the view
    # permission, which is still mapped.
    perms_map = dict(DefaultDjangoModelPermissions.perms_map,
                     POST=[], PUT=[], PATCH=[], DELETE=[])


class BaseJobScopeList(ListCreateAPIViewWithAudit):
    permission_classes = [JobScopePermissions]
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("configuration", "job")
    create_pbac_request_class = None

    def perform_create(self, serializer):
        # After the validation, so the configuration and the job are instances, not primary keys
        # that can be absent. The DRF permission layer runs first, and has nothing to name.
        pbac_request = self.create_pbac_request_class(self.request.user,
                                                      serializer.validated_data["configuration"],
                                                      serializer.validated_data["job"])
        check_request(self.request, pbac_request)
        super().perform_create(serializer)


class BaseJobScopeDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    permission_classes = [JobScopePermissions]
    update_pbac_request_class = None
    delete_pbac_request_class = None

    def perform_update(self, serializer):
        # The instance, not validated_data. The schedule is the resource, and the serializer
        # already refuses a different configuration or job.
        check_request(self.request, self.update_pbac_request_class(self.request.user, serializer.instance))
        super().perform_update(serializer)

    def perform_destroy(self, instance):
        check_request(self.request, self.delete_pbac_request_class(self.request.user, instance))
        super().perform_destroy(instance)
