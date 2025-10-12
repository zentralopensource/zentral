from django_filters import rest_framework as filters
from rest_framework.generics import ListAPIView, RetrieveAPIView
from zentral.contrib.mdm.models import Location, LocationAsset
from zentral.contrib.mdm.serializers import LocationAssetSerializer, LocationSerializer
from zentral.utils.drf import DefaultDjangoModelPermissions


class LocationList(ListAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name', 'organization_name', 'mdm_info_id')


class LocationDetail(RetrieveAPIView):
    queryset = Location.objects.all()
    serializer_class = LocationSerializer
    permission_classes = [DefaultDjangoModelPermissions]


class LocationAssetFilter(filters.FilterSet):
    location_id = filters.ModelChoiceFilter(field_name="location", queryset=Location.objects.all())
    adam_id = filters.CharFilter(field_name="asset__adam_id")
    pricing_param = filters.CharFilter(field_name="asset__pricing_param")


class LocationAssetList(ListAPIView):
    queryset = LocationAsset.objects.all()
    serializer_class = LocationAssetSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = LocationAssetFilter
