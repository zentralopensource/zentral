from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from zentral.contrib.mdm.models import OTAEnrollment
from zentral.contrib.mdm.serializers import OTAEnrollmentSerializer


class OTAEnrollmentList(ListCreateAPIViewWithAudit):
    """
    List all OTAEnrollment, search OTAEnrollment by name,
    or create a new OTAEnrollment.
    """
    queryset = OTAEnrollment.objects.all()
    serializer_class = OTAEnrollmentSerializer
    filterset_fields = ('name',)
    pagination_class = MaxLimitOffsetPagination


class OTAEnrollmentDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a OTAEnrollment instance.
    """
    queryset = OTAEnrollment.objects.all()
    serializer_class = OTAEnrollmentSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This OTA enrollment cannot be deleted')
        else:
            return super().perform_destroy(instance)
