from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView, RetrieveAPIView
from zentral.contrib.mdm.models import PushCertificate
from zentral.contrib.mdm.serializers import PushCertificateSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions


class PushCertificateList(ListAPIView):
    queryset = PushCertificate.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = PushCertificateSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class PushCertificateDetail(RetrieveAPIView):
    queryset = PushCertificate.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = PushCertificateSerializer
