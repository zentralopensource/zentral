import uuid
from django.db import transaction
from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django_filters import rest_framework as filters
from rest_framework import generics
from rest_framework.exceptions import ValidationError
from rest_framework.parsers import JSONParser
from rest_framework.response import Response
from rest_framework.serializers import ModelSerializer
from rest_framework.views import APIView
from base.notifier import notifier
from zentral.core.events.base import AuditEvent, EventRequest
from zentral.utils.drf import (DjangoPermissionRequired, DefaultDjangoModelPermissions,
                               ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit)
from zentral.utils.http import user_agent_and_ip_address_from_request
from .events import post_monolith_cache_server_update_request, post_monolith_sync_catalogs_request
from .models import (CacheServer, Catalog, Condition, Enrollment,
                     Manifest, ManifestCatalog, ManifestEnrollmentPackage,  ManifestSubManifest,
                     Repository,
                     SubManifest, SubManifestPkgInfo)
from .repository_backends import load_repository_backend
from .serializers import (CatalogSerializer, ConditionSerializer,
                          EnrollmentSerializer,
                          ManifestCatalogSerializer, ManifestEnrollmentPackageSerializer,
                          ManifestSerializer, ManifestSubManifestSerializer,
                          RepositorySerializer,
                          SubManifestSerializer, SubManifestPkgInfoSerializer)
from .utils import build_configuration_plist, build_configuration_profile


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


class SyncRepository(APIView):
    permission_required = "monolith.sync_repository"
    permission_classes = [DjangoPermissionRequired]

    def initialize_events(self, request):
        self.events = []
        self.event_uuid = uuid.uuid4()
        self.event_index = 0
        self.event_request = EventRequest.build_from_request(request)

    def audit_callback(self, instance, action, prev_value=None):
        event = AuditEvent.build(
            instance, action, prev_value=prev_value,
            event_uuid=self.event_uuid, event_index=self.event_index,
            event_request=self.event_request
        )
        event.metadata.add_objects({"monolith_repository": ((self.db_repository.pk,),)})
        self.events.append(event)
        self.event_index += 1

    def post_events(self):
        for event in self.events:
            event.post()

    def post(self, request, *args, **kwargs):
        self.db_repository = get_object_or_404(Repository, pk=kwargs["pk"])
        post_monolith_sync_catalogs_request(request, self.db_repository)
        repository = load_repository_backend(self.db_repository)
        self.initialize_events(request)
        repository.sync_catalogs(self.audit_callback)
        transaction.on_commit(lambda: self.post_events())
        return Response({"status": 0})


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


# catalogs


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


# conditions


class ConditionList(generics.ListCreateAPIView):
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer
    permission_classes = (DefaultDjangoModelPermissions,)
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('name',)


class ConditionDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Condition.objects.all()
    serializer_class = ConditionSerializer
    permission_classes = (DefaultDjangoModelPermissions,)

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This condition cannot be deleted')
        return super().perform_destroy(instance)


# enrollments


class EnrollmentList(generics.ListCreateAPIView):
    """
    List all Enrollments or create a new Enrollment
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
    serializer_class = EnrollmentSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('manifest_id',)


class EnrollmentDetail(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update or delete an Enrollment
    """
    queryset = Enrollment.objects.all()
    permission_classes = [DefaultDjangoModelPermissions]
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


class ManifestList(generics.ListCreateAPIView):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("meta_business_unit_id", "name")


class ManifestDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = Manifest.objects.all()
    serializer_class = ManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]


# manifest catalogs


class ManifestCatalogList(generics.ListCreateAPIView):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("manifest_id", "catalog_id")


class ManifestCatalogDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ManifestCatalog.objects.all()
    serializer_class = ManifestCatalogSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


class ManifestEnrollmentPackageList(generics.ListCreateAPIView):
    queryset = ManifestEnrollmentPackage.objects.all()
    serializer_class = ManifestEnrollmentPackageSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("manifest_id", "builder")


class ManifestEnrollmentPackageDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ManifestEnrollmentPackage.objects.all()
    serializer_class = ManifestEnrollmentPackageSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


# manifest sub manifests


class ManifestSubManifestList(generics.ListCreateAPIView):
    queryset = ManifestSubManifest.objects.all()
    serializer_class = ManifestSubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ("manifest_id", "sub_manifest_id")


class ManifestSubManifestDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = ManifestSubManifest.objects.all()
    serializer_class = ManifestSubManifestSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        manifest = instance.manifest
        response = super().perform_destroy(instance)
        manifest.bump_version()
        return response


# sub manifests


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


# sub manifest pkg infos


class SubManifestPkgInfoList(generics.ListCreateAPIView):
    queryset = SubManifestPkgInfo.objects.all()
    serializer_class = SubManifestPkgInfoSerializer
    permission_classes = [DefaultDjangoModelPermissions]
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('sub_manifest_id',)


class SubManifestPkgInfoDetail(generics.RetrieveUpdateDestroyAPIView):
    queryset = SubManifestPkgInfo.objects.all()
    serializer_class = SubManifestPkgInfoSerializer
    permission_classes = [DefaultDjangoModelPermissions]

    def perform_destroy(self, instance):
        sub_manifest = instance.sub_manifest
        response = super().perform_destroy(instance)
        for _, manifest in sub_manifest.manifests_with_tags():
            manifest.bump_version()
        return response
