from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import MSCPCheck
from ..serializers import MSCPCheckSerializer


class MSCPCheckList(ListCreateAPIViewWithAudit):
    queryset = MSCPCheck.objects.select_related("job").all()
    serializer_class = MSCPCheckSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("rule_id", "baseline")


class MSCPCheckDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = MSCPCheck.objects.select_related("job").all()
    serializer_class = MSCPCheckSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This mSCP check cannot be deleted")
        return super().perform_destroy(instance)
