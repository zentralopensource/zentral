from django.db import transaction
from django.db.models import F
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.exceptions import ValidationError
from rest_framework.filters import OrderingFilter
from zentral.utils.drf import (ListCreateAPIViewWithAudit,
                               MaxLimitOffsetPagination,
                               RetrieveUpdateDestroyAPIViewWithAudit)
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import (Artifact,
                                        CertAsset, DataAsset, Declaration,
                                        EnterpriseApp, Profile, ProvisioningProfile, StoreApp)
from zentral.contrib.mdm.serializers import (ArtifactSerializer, CertAssetSerializer,
                                             DataAssetSerializer, DeclarationSerializer,
                                             EnterpriseAppSerializer, ProfileSerializer,
                                             ProvisioningProfileSerializer, StoreAppSerializer)


# artifact version satellites

# CertAsset, DataAsset, Declaration, Profile, ProvisioningProfile, EnterpriseApp and StoreApp are
# one-to-one satellites of ArtifactVersion and have no timestamps of their own. The ordering keys are
# annotated from the artifact version, so that ?ordering= takes the names the serializers expose.
class ArtifactVersionOrderingMixin:
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    ordering_fields = ("created_at", "updated_at")
    # LIMIT/OFFSET pagination is only stable on a total order, and created_at is not unique: without
    # the pk tiebreaker a tie straddling a page boundary can skip rows and repeat others.
    ordering = ["-created_at", "-pk"]

    def get_queryset(self):
        return super().get_queryset().annotate(
            created_at=F("artifact_version__created_at"),
            updated_at=F("artifact_version__updated_at"),
        ).order_by(*self.ordering)


# artifacts


class ArtifactList(ListCreateAPIViewWithAudit):
    """
    List all Artifacts, search Artifact by name, or create a new Artifact.
    """
    queryset = Artifact.objects.all().order_by("-created_at", "-pk")
    serializer_class = ArtifactSerializer
    filter_backends = (DjangoFilterBackend, OrderingFilter)
    filterset_fields = ('name',)
    ordering_fields = ('created_at', 'updated_at')
    ordering = ['-created_at', '-pk']
    pagination_class = MaxLimitOffsetPagination

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


# cert assets


class CertAssetList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all CertAssets or create a new CertAsset
    """
    queryset = (CertAsset.objects
                         .select_related("artifact_version__cert_asset__acme_issuer",
                                         "artifact_version__cert_asset__scep_issuer")
                         .prefetch_related("artifact_version__excluded_tags",
                                           "artifact_version__item_tags__tag__meta_business_unit",
                                           "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = CertAssetSerializer
    pagination_class = MaxLimitOffsetPagination

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class CertAssetDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a CertAsset instance.
    """
    queryset = (CertAsset.objects
                         .select_related("artifact_version__cert_asset__acme_issuer",
                                         "artifact_version__cert_asset__scep_issuer")
                         .prefetch_related("artifact_version__excluded_tags",
                                           "artifact_version__item_tags__tag__meta_business_unit",
                                           "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = CertAssetSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This cert asset cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response


# data assets


class DataAssetList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all DataAssets or create a new DataAsset
    """
    queryset = (DataAsset.objects
                         .select_related("artifact_version__data_asset")
                         .prefetch_related("artifact_version__excluded_tags",
                                           "artifact_version__item_tags__tag__meta_business_unit",
                                           "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DataAssetSerializer
    pagination_class = MaxLimitOffsetPagination

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


class DeclarationList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all Declarations or create a new Declaration.
    """
    queryset = (Declaration.objects
                           .select_related("artifact_version__artifact")
                           .prefetch_related("artifact_version__excluded_tags",
                                             "artifact_version__item_tags__tag__meta_business_unit",
                                             "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = DeclarationSerializer
    pagination_class = MaxLimitOffsetPagination

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


class ProfileList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all Profiles or create a new Profile
    """
    queryset = (Profile.objects
                       .select_related("artifact_version__artifact")
                       .prefetch_related("artifact_version__excluded_tags",
                                         "artifact_version__item_tags__tag__meta_business_unit",
                                         "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = ProfileSerializer
    pagination_class = MaxLimitOffsetPagination

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


# provisioning profiles


class ProvisioningProfileList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all Provisioning Profiles or create a new Provisioning Profile
    """
    queryset = (ProvisioningProfile.objects
                                   .select_related("artifact_version__artifact")
                                   .prefetch_related("artifact_version__excluded_tags",
                                                     "artifact_version__item_tags__tag__meta_business_unit",
                                                     "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = ProvisioningProfileSerializer
    pagination_class = MaxLimitOffsetPagination

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class ProvisioningProfileDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Provisioning Profile instance.
    """
    queryset = (ProvisioningProfile.objects
                                   .select_related("artifact_version__artifact")
                                   .prefetch_related("artifact_version__excluded_tags",
                                                     "artifact_version__item_tags__tag__meta_business_unit",
                                                     "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = ProvisioningProfileSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This provisioning profile cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response


# enterprise apps


class EnterpriseAppList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all EnterpriseApps or create a new EnterpriseApp
    """
    queryset = (EnterpriseApp.objects
                             .select_related("artifact_version__artifact")
                             .prefetch_related("artifact_version__excluded_tags",
                                               "artifact_version__item_tags__tag__meta_business_unit",
                                               "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = EnterpriseAppSerializer
    pagination_class = MaxLimitOffsetPagination

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

# store apps


class StoreAppList(ArtifactVersionOrderingMixin, ListCreateAPIViewWithAudit):
    """
    List all StoreApps or create a new StoreApp
    """
    queryset = (StoreApp.objects
                        .select_related("artifact_version__artifact")
                        .prefetch_related("artifact_version__excluded_tags",
                                          "artifact_version__item_tags__tag__meta_business_unit",
                                          "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = StoreAppSerializer
    pagination_class = MaxLimitOffsetPagination

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class StoreAppDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a StoreApp instance.
    """
    queryset = (StoreApp.objects
                        .select_related("artifact_version__artifact")
                        .prefetch_related("artifact_version__excluded_tags",
                                          "artifact_version__item_tags__tag__meta_business_unit",
                                          "artifact_version__item_tags__tag__taxonomy"))
    serializer_class = StoreAppSerializer
    lookup_field = "artifact_version__pk"
    lookup_url_kwarg = "artifact_version_pk"

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            if not instance.artifact_version.can_be_deleted():
                raise ValidationError('This store app cannot be deleted')
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return response
