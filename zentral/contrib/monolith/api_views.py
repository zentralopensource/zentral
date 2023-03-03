from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.serializers import ModelSerializer
from rest_framework.views import APIView
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.utils.drf import DjangoPermissionRequired, DefaultDjangoModelPermissions
from zentral.utils.http import user_agent_and_ip_address_from_request
from .conf import monolith_conf
from .events import post_monolith_cache_server_update_request, post_monolith_sync_catalogs_request
from .models import CacheServer, Catalog, Manifest, ManifestCatalog, SubManifest
from .serializers import CatalogSerializer, ManifestSerializer, ManifestCatalogSerializer, SubManifestSerializer


class SyncRepository(APIView):
    permission_required = (
        "monolith.view_catalog", "monolith.add_catalog", "monolith.change_catalog",
        "monolith.view_pkginfoname", "monolith.add_pkginfoname", "monolith.change_pkginfoname",
        "monolith.view_pkginfo", "monolith.add_pkginfo", "monolith.change_pkginfo",
        "monolith.change_manifest"
    )
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        post_monolith_sync_catalogs_request(request)
        monolith_conf.repository.sync_catalogs()
        return Response({"status": 0})


class CacheServerSerializer(ModelSerializer):
    class Meta:
        model = CacheServer
        fields = ("name", "base_url")


class UpdateCacheServer(APIView):
    parser_classes = [JSONParser]
    permission_required = ("monolith.change_manifest", "monolith.add_cacheserver", "monolith.change_cacheserver")
    permission_classes = [DjangoPermissionRequired]

    def post(self, request, *args, **kwargs):
        manifest = get_object_or_404(Manifest, pk=kwargs["pk"])
        serializer = CacheServerSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except ValidationError as e:
            post_monolith_cache_server_update_request(request, errors=e.detail)
            raise
        defaults = serializer.data.copy()
        name = defaults.pop("name")
        _, public_ip_address = user_agent_and_ip_address_from_request(request)
        defaults["public_ip_address"] = public_ip_address
        cache_server, _ = CacheServer.objects.update_or_create(
            manifest=manifest,
            name=name,
            defaults=defaults
        )
        post_monolith_cache_server_update_request(request, cache_server=cache_server)
        return Response({"status": 0})


class CatalogList(generics.ListCreateAPIView):
    queryset = Catalog.objects.all()
    serializer_class = CatalogSerializer
    permission_classes = (DefaultDjangoModelPermissions,)
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class CatalogDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Catalog.objects.all()
    serializer_class = CatalogSerializer
    permission_classes = (DefaultDjangoModelPermissions,)

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This catalog cannot be deleted')
        return super().perform_destroy(instance)


class ManifestFilter(filters.FilterSet):
    meta_business_unit_id = filters.ModelChoiceFilter(queryset=MetaBusinessUnit.objects.all())
    name = filters.CharFilter()


class ManifestList(generics.ListCreateAPIView):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = ManifestFilter


class ManifestDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]


class ManifestCatalogFilter(filters.FilterSet):
    manifest_id = filters.ModelChoiceFilter(queryset=Manifest.objects.all())
    catalog_id = filters.ModelChoiceFilter(queryset=Catalog.objects.all())


class ManifestCatalogList(generics.ListCreateAPIView):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = ManifestCatalogFilter


class ManifestCatalogDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]


class SubManifestList(generics.ListCreateAPIView):
    queryset = SubManifest.objects.all()
    serializer_class = SubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class SubManifestDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = SubManifest.objects.all()
    serializer_class = SubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
