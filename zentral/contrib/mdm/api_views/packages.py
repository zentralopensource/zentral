from rest_framework.exceptions import ValidationError
from zentral.utils.drf import (ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from zentral.contrib.mdm.models import Package
from zentral.contrib.mdm.serializers import PackageSerializer


class PackageList(ListCreateAPIViewWithAudit):
    """
    List all Packages, search Packages by name, or create a new Package.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer
    filterset_fields = ("name",)
    pagination_class = MaxLimitOffsetPagination


class PackageDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Package instance.
    """
    queryset = Package.objects.all()
    serializer_class = PackageSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError("This package cannot be deleted")
        return super().perform_destroy(instance)
