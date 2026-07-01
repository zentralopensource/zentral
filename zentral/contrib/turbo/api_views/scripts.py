from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Script
from ..serializers import ScriptSerializer


class ScriptList(ListCreateAPIViewWithAudit):
    queryset = Script.objects.select_related("job").all()
    serializer_class = ScriptSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("name",)


class ScriptDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Script.objects.select_related("job").all()
    serializer_class = ScriptSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This script cannot be deleted")
        return super().perform_destroy(instance)
