from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit, MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from ..models import Configuration
from ..serializers import ConfigurationSerializer


class ConfigurationList(ListCreateAPIViewWithAudit):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer
    pagination_class = MaxLimitOffsetPagination
    filterset_fields = ("name",)


class ConfigurationDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Configuration.objects.all()
    serializer_class = ConfigurationSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This configuration cannot be deleted")
        return super().perform_destroy(instance)
