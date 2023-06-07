from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.models import Blueprint
from zentral.contrib.mdm.serializers import BlueprintSerializer


class BlueprintList(ListCreateAPIViewWithAudit):
    """
    List all Blueprints, search Blueprint by name, or create a new Blueprint.
    """
    queryset = Blueprint.objects.all()
    serializer_class = BlueprintSerializer
    filterset_fields = ('name',)


class BlueprintDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Blueprint instance.
    """
    queryset = Blueprint.objects.all()
    serializer_class = BlueprintSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This blueprint cannot be deleted')
        else:
            return super().perform_destroy(instance)
