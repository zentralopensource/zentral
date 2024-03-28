from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView
from zentral.contrib.mdm.models import Location
from zentral.contrib.mdm.serializers import LocationSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions


class LocationList(ListAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name', 'organization_name')
