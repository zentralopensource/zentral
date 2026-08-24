import logging

from accounts.api_authentication import APITokenAuthentication
from base.notifier import notifier
from base.serializers import TaskSerializer
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics, status
from rest_framework.authentication import SessionAuthentication
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.serializers import ModelSerializer
from rest_framework.views import APIView

from zentral.core.events.base import EventRequest
from zentral.utils.drf import (
    DefaultDjangoModelPermissions,
    DjangoPermissionRequired,
    ListCreateAPIViewWithAudit,
    MaxLimitOffsetPagination,
    RetrieveUpdateDestroyAPIViewWithAudit,
)
from zentral.utils.http import user_agent_and_ip_address_from_request

from .events import post_monolith_cache_server_update_request, post_monolith_sync_catalogs_request
from .models import (
    CacheServer,
    Catalog,
    Condition,
    Enrollment,
    Manifest,
    ManifestCatalog,
    ManifestEnrollmentPackage,
    ManifestSubManifest,
    Repository,
    SubManifest,
    SubManifestPkgInfo,
)
from .serializers import (
    CatalogSerializer,
    ConditionSerializer,
    EnrollmentSerializer,
    ManifestCatalogSerializer,
    ManifestEnrollmentPackageSerializer,
    ManifestSerializer,
    ManifestSubManifestSerializer,
    RepositorySerializer,
    SubManifestPkgInfoSerializer,
    SubManifestSerializer,
)
from .tasks import sync_repository_task
from .utils import build_configuration_plist, build_configuration_profile

logger = logging.getLogger("zentral.contrib.monolith.api_views")


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


# repositories


class SyncRepository(generics.GenericAPIView):
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "monolith.sync_repository"
    permission_classes = [DjangoPermissionRequired]
    serializer_class = TaskSerializer

    def post(self, request, *args, **kwargs):
        db_repository = get_object_or_404(Repository, pk=kwargs["pk"])
        post_monolith_sync_catalogs_request(request, db_repository)
        task = sync_repository_task.apply_async(
            (db_repository.pk,),
            {"serialized_event_request": EventRequest.build_from_request(request).serialize(),
             "task_user": request.user.id}
        )
        serializer = self.serializer_class.from_task(task=task)
        return Response(serializer.initial_data, status=status.HTTP_201_CREATED)


class RepositoryList(ListCreateAPIViewWithAudit):
    queryset = Repository.objects.all()
    serializer_class = RepositorySerializer
    filterset_fields = ('name',)

    def on_commit_callback_extra(self, instance):
        notifier.send_notification("monolith.repository", str(instance.pk))


class RepositoryDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Repository.objects.all()
    serializer_class = RepositorySerializer

    def on_commit_callback_extra(self, instance):
        notifier.send_notification("monolith.repository", str(instance.pk))

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This repository cannot be deleted')
        return super().perform_destroy(instance)

    def perform_update(self, serializer):
        if not serializer.instance.can_be_updated():
            raise ValidationError('This repository cannot be updated')
        return super().perform_update(serializer)


# catalogs


class CatalogList(ListCreateAPIViewWithAudit):
    queryset = Catalog.objects.all()
    serializer_class = CatalogSerializer
    filterset_fields = ('name', 'repository')
    pagination_class = MaxLimitOffsetPagination


class CatalogDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Catalog.objects.all()
    serializer_class = CatalogSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This catalog cannot be deleted')
        return super().perform_destroy(instance)


# conditions


class ConditionList(ListCreateAPIViewWithAudit):
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer
    filterset_fields = ('name',)


class ConditionDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This condition cannot be deleted')
        return super().perform_destroy(instance)


# enrollments


class EnrollmentList(ListCreateAPIViewWithAudit):
    """
    List all Enrollments or create a new Enrollment
    """
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer
    filterset_fields = ('manifest_id',)


class EnrollmentDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete an Enrollment
    """
    queryset = Enrollment.objects.all()
    serializer_class = EnrollmentSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This enrollment cannot be deleted')
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


class EnrollmentConfiguration(APIView):
    """
    base enrollment configuration class. To be subclassed.
    """
    authentication_classes = [APITokenAuthentication, SessionAuthentication]
    permission_required = "monolith.view_enrollment"
    permission_classes = [DjangoPermissionRequired]

    def get_content(self, enrollment):
        raise NotImplementedError

    def get(self, request, *args, **kwargs):
        enrollment = get_object_or_404(Enrollment, pk=kwargs["pk"])
        filename, content_type, content = self.get_content(enrollment)
        response = HttpResponse(content, content_type=content_type)
        response["Content-Disposition"] = 'attachment; filename="{}"'.format(filename)
        response["Content-Length"] = len(content)
        return response


class EnrollmentPlist(EnrollmentConfiguration):
    """
    Download enrollment plist file
    """

    def get_content(self, enrollment):
        filename, content = build_configuration_plist(enrollment)
        return filename, "application/x-plist", content


class EnrollmentConfigurationProfile(EnrollmentConfiguration):
    """
    Download enrollment configuration_profile
    """

    def get_content(self, enrollment):
        filename, content = build_configuration_profile(enrollment)
        return filename, "application/octet-stream", content


# manifests


class ManifestList(ListCreateAPIViewWithAudit):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("meta_business_unit_id", "name")


class ManifestDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]


# manifest catalogs


class ManifestCatalogList(ListCreateAPIViewWithAudit):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("manifest_id", "catalog_id")


class ManifestCatalogDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


class ManifestEnrollmentPackageList(ListCreateAPIViewWithAudit):
    queryset = ManifestEnrollmentPackage.objects.all()
    serializer_class = ManifestEnrollmentPackageSerializer
    filterset_fields = ("manifest_id", "builder")


class ManifestEnrollmentPackageDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ManifestEnrollmentPackage.objects.all()
    serializer_class = ManifestEnrollmentPackageSerializer

    def get_perform_destroy_kwargs(self):
        # the API takes an enrollment it did not create, so it releases it instead of deleting it
        return {"delete_enrollment": False}

    def perform_destroy(self, instance):
        manifest = instance.manifest
        super().perform_destroy(instance)
        manifest.bump_version()


# manifest sub manifests


class ManifestSubManifestList(ListCreateAPIViewWithAudit):
    queryset = ManifestSubManifest.objects.all()
    serializer_class = ManifestSubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("manifest_id", "sub_manifest_id")


class ManifestSubManifestDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = ManifestSubManifest.objects.all()
    serializer_class = ManifestSubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


# sub manifests


class SubManifestList(ListCreateAPIViewWithAudit):
    queryset = SubManifest.objects.all()
    serializer_class = SubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class SubManifestDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = SubManifest.objects.all()
    serializer_class = SubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]


# sub manifest pkg infos


class SubManifestPkgInfoList(ListCreateAPIViewWithAudit):
    queryset = SubManifestPkgInfo.objects.all()
    serializer_class = SubManifestPkgInfoSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('sub_manifest_id',)


class SubManifestPkgInfoDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    queryset = SubManifestPkgInfo.objects.all()
    serializer_class = SubManifestPkgInfoSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        sub_manifest = instance.sub_manifest
        response = super().perform_destroy(instance)
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return response
