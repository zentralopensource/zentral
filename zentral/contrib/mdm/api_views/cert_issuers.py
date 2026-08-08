from rest_framework.exceptions import ValidationError
from zentral.contrib.mdm.models import ACMEIssuer, SCEPIssuer
from zentral.contrib.mdm.serializers import ACMEIssuerSerializer, SCEPIssuerSerializer
from zentral.utils.drf import (ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)


class ACMEIssuerList(ListCreateAPIViewWithAudit):
    queryset = ACMEIssuer.objects.order_by("name")
    serializer_class = ACMEIssuerSerializer
    filterset_fields = ('name',)
    pagination_class = MaxLimitOffsetPagination


class ACMEIssuerDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ACMEIssuer.objects.all()
    serializer_class = ACMEIssuerSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This ACME issuer cannot be deleted.")
        super().perform_destroy(instance)

    def perform_update(self, serializer):
        if not serializer.instance.can_be_updated():
            raise ValidationError("This ACME issuer cannot be updated.")
        super().perform_update(serializer)


class SCEPIssuerList(ListCreateAPIViewWithAudit):
    queryset = SCEPIssuer.objects.order_by("name")
    serializer_class = SCEPIssuerSerializer
    filterset_fields = ('name',)
    pagination_class = MaxLimitOffsetPagination


class SCEPIssuerDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = SCEPIssuer.objects.all()
    serializer_class = SCEPIssuerSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This SCEP issuer cannot be deleted.")
        super().perform_destroy(instance)

    def perform_update(self, serializer):
        if not serializer.instance.can_be_updated():
            raise ValidationError("This SCEP issuer cannot be updated.")
        super().perform_update(serializer)
