from django_filters import rest_framework as filters
from rest_framework import generics
from .models import MetaBusinessUnit
from .serializers import MetaBusinessUnitSerializer


class MetaBusinessUnitList(generics.ListCreateAPIView):
    """
    List all MBUs, search MBU by name, or create a new MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    serializer_class = MetaBusinessUnitSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class MetaBusinessUnitDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a MBU instance.
    """
    queryset = MetaBusinessUnit.objects.all()
    serializer_class = MetaBusinessUnitSerializer
