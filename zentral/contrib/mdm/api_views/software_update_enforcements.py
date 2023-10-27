from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.models import SoftwareUpdateEnforcement
from zentral.contrib.mdm.serializers import SoftwareUpdateEnforcementSerializer


class SoftwareUpdateEnforcementList(ListCreateAPIViewWithAudit):
    """
    List all SoftwareUpdateEnforcement, search SoftwareUpdateEnforcement by name,
    or create a new SoftwareUpdateEnforcement.
    """
    queryset = SoftwareUpdateEnforcement.objects.all()
    serializer_class = SoftwareUpdateEnforcementSerializer
    filterset_fields = ('name',)


class SoftwareUpdateEnforcementDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a SoftwareUpdateEnforcement instance.
    """
    queryset = SoftwareUpdateEnforcement.objects.all()
    serializer_class = SoftwareUpdateEnforcementSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This software update enforcement cannot be deleted')
        else:
            return super().perform_destroy(instance)
