from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView, RetrieveAPIView
from zentral.contrib.mdm.models import SCEPConfig
from zentral.contrib.mdm.serializers import SCEPConfigSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions


class SCEPConfigList(ListAPIView):
    queryset = SCEPConfig.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = SCEPConfigSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class SCEPConfigDetail(RetrieveAPIView):
    queryset = SCEPConfig.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = SCEPConfigSerializer
