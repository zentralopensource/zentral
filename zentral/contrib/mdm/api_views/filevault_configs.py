from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.models import FileVaultConfig
from zentral.contrib.mdm.serializers import FileVaultConfigSerializer


class FileVaultConfigList(ListCreateAPIViewWithAudit):
    """
    List all FileVaultConfig, search FileVaultConfig by name, or create a new FileVaultConfig.
    """
    queryset = FileVaultConfig.objects.all()
    serializer_class = FileVaultConfigSerializer
    filterset_fields = ('name',)


class FileVaultConfigDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a FileVaultConfig instance.
    """
    queryset = FileVaultConfig.objects.all()
    serializer_class = FileVaultConfigSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This FileVault configuration cannot be deleted')
        else:
            return super().perform_destroy(instance)
