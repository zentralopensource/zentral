from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.models import RecoveryPasswordConfig
from zentral.contrib.mdm.serializers import RecoveryPasswordConfigSerializer


class RecoveryPasswordConfigList(ListCreateAPIViewWithAudit):
    """
    List all RecoveryPasswordConfig, search RecoveryPasswordConfig by name, or create a new RecoveryPasswordConfig.
    """
    queryset = RecoveryPasswordConfig.objects.all()
    serializer_class = RecoveryPasswordConfigSerializer
    filterset_fields = ('name',)


class RecoveryPasswordConfigDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a RecoveryPasswordConfig instance.
    """
    queryset = RecoveryPasswordConfig.objects.all()
    serializer_class = RecoveryPasswordConfigSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This recovery password configuration cannot be deleted')
        else:
            return super().perform_destroy(instance)
