from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from .models import MetaBusinessUnit, Tag
from .serializers import MetaBusinessUnitSerializer, TagSerializer


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
    Retrieve, update or delete a MBU.
    """
    queryset = MetaBusinessUnit.objects.all()
    serializer_class = MetaBusinessUnitSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This meta business unit cannot be deleted')
        else:
            return super().perform_destroy(instance)


class TagList(generics.ListCreateAPIView):
    """
    List all tags, search tag by name, or create a new tag.
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class TagDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete a tag.
    """
    queryset = Tag.objects.all()
    serializer_class = TagSerializer
