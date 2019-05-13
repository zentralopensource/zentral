from django.urls import reverse
from django.utils import timezone
from django_filters import rest_framework as filters
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import MetaBusinessUnit, Tag
from .serializers import MetaBusinessUnitSerializer, TagSerializer
from .tasks import export_inventory
from .utils import MSQuery


class MachinesExport(APIView):
    def post(self, request, *args, **kwargs):
        export_format = request.GET.get("export_format", "xlsx")
        if export_format not in ("xlsx", "zip"):
            raise ValidationError("Unknown export format")
        msquery = MSQuery(request.GET)
        filename = "inventory_export_{:%Y-%m-%d_%H-%M-%S}.{}".format(timezone.now(), export_format)
        result = export_inventory.apply_async((msquery.get_urlencoded_canonical_query_dict(), filename))
        return Response({"task_id": result.id,
                         "task_result_url": reverse("base_api:task_result", args=(result.id,))},
                        status=status.HTTP_201_CREATED)


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
