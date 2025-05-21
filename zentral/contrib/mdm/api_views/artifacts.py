from django.db import transaction
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import Artifact, DataAsset, Declaration, EnterpriseApp, Profile
from zentral.contrib.mdm.serializers import (ArtifactSerializer, DataAssetSerializer, DeclarationSerializer,
                                             EnterpriseAppSerializer, ProfileSerializer)


# artifacts


class ArtifactList(ListCreateAPIViewWithAudit):
    """
    List all Artifacts, search Artifact by name, or create a new Artifact.
    """
    queryset = Artifact.objects.all()
    serializer_class = ArtifactSerializer
    filterset_fields = ('name',)

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class ArtifactDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete an Artifact instance.
    """
    queryset = Artifact.objects.all()
    serializer_class = ArtifactSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    @transaction.atomic(durable=True)
    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This artifact cannot be deleted')
        else:
            return super().perform_destroy(instance)


# data assets


class DataAssetList(ListCreateAPIViewWithAudit):
    """
    List all DataAssets or create a new DataAsset
    """
    queryset = (DataAsset.objects
                         .select_related("artifact_version__data_asset")
                         .prefetch_related("artifact_version__excluded_tags",
                                           "artifact_version__item_tags__tag__meta_business_unit",
                                           "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DataAssetSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class DataAssetDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a DataAsset instance.
    """
    queryset = (DataAsset.objects
                         .select_related("artifact_version__data_asset")
                         .prefetch_related("artifact_version__excluded_tags",
                                           "artifact_version__item_tags__tag__meta_business_unit",
                                           "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DataAssetSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This data asset cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response


# declarations


class DeclarationList(ListCreateAPIViewWithAudit):
    """
    List all Declarations or create a new Declaration.
    """
    queryset = (Declaration.objects
                           .select_related("artifact_version__artifact")
                           .prefetch_related("artifact_version__excluded_tags",
                                             "artifact_version__item_tags__tag__meta_business_unit",
                                             "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DeclarationSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class DeclarationDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Declaration instance.
    """
    queryset = (Declaration.objects
                           .select_related("artifact_version__artifact")
                           .prefetch_related("artifact_version__excluded_tags",
                                             "artifact_version__item_tags__tag__meta_business_unit",
                                             "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DeclarationSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This declaration cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response


# profiles


class ProfileList(ListCreateAPIViewWithAudit):
    """
    List all Profiles or create a new Profile
    """
    queryset = (Profile.objects
                       .select_related("artifact_version__artifact")
                       .prefetch_related("artifact_version__excluded_tags",
                                         "artifact_version__item_tags__tag__meta_business_unit",
                                         "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = ProfileSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class ProfileDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Profile instance.
    """
    queryset = (Profile.objects
                       .select_related("artifact_version__artifact")
                       .prefetch_related("artifact_version__excluded_tags",
                                         "artifact_version__item_tags__tag__meta_business_unit",
                                         "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = ProfileSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This profile cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response


# enterprise apps


class EnterpriseAppList(ListCreateAPIViewWithAudit):
    """
    List all EnterpriseApps or create a new EnterpriseApp
    """
    queryset = (EnterpriseApp.objects
                             .select_related("artifact_version__artifact")
                             .prefetch_related("artifact_version__excluded_tags",
                                               "artifact_version__item_tags__tag__meta_business_unit",
                                               "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = EnterpriseAppSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class EnterpriseAppDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a EnterpriseApp instance.
    """
    queryset = (EnterpriseApp.objects
                             .select_related("artifact_version__artifact")
                             .prefetch_related("artifact_version__excluded_tags",
                                               "artifact_version__item_tags__tag__meta_business_unit",
                                               "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = EnterpriseAppSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This enterprise app cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response
