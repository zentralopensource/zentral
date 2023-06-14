from django.db import transaction
from rest_framework.exceptions import ValidationError
from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.models import Blueprint, BlueprintArtifact
from zentral.contrib.mdm.serializers import BlueprintSerializer, BlueprintArtifactSerializer


class BlueprintList(ListCreateAPIViewWithAudit):
    """
    List all Blueprints, search Blueprint by name, or create a new Blueprint.
    """
    queryset = Blueprint.objects.all()
    serializer_class = BlueprintSerializer
    filterset_fields = ('name',)


class BlueprintDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Blueprint instance.
    """
    queryset = Blueprint.objects.all()
    serializer_class = BlueprintSerializer

    def perform_destroy(self, instance):
        if not instance.can_be_deleted():
            raise ValidationError('This blueprint cannot be deleted')
        else:
            return super().perform_destroy(instance)


class BlueprintArtifactList(ListCreateAPIViewWithAudit):
    """
    List all Blueprint Artifacts, search Blueprint Artifact by name, or create a new Blueprint Artifact.
    """
    queryset = (BlueprintArtifact.objects
                                 .select_related("blueprint", "artifact")
                                 .prefetch_related("excluded_tags",
                                                   "item_tags__tag__meta_business_unit",
                                                   "item_tags__tag__taxonomy")
                                 .all())
    serializer_class = BlueprintArtifactSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class BlueprintArtifactDetail(RetrieveUpdateDestroyAPIViewWithAudit):
    """
    Retrieve, update or delete a Blueprint Artifact instance.
    """
    queryset = (BlueprintArtifact.objects
                                 .select_related("blueprint", "artifact")
                                 .prefetch_related("excluded_tags",
                                                   "item_tags__tag__meta_business_unit",
                                                   "item_tags__tag__taxonomy")
                                 .all())
    serializer_class = BlueprintArtifactSerializer

    @transaction.non_atomic_requests
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def perform_destroy(self, instance):
        with transaction.atomic(durable=True):
            response = super().perform_destroy(instance)
        with transaction.atomic(durable=True):
            update_blueprint_serialized_artifacts(instance.blueprint)
        return response
