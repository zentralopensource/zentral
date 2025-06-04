from django.utils.text import slugify
from rest_framework import serializers
from zentral.core.incidents.models import Severity
from .action_backends.http import HTTPPostActionSerializer
from .action_backends.slack import SlackIncomingWebhookActionSerializer
from .probe import InventoryFilterSerializer, MetadataFilterSerializer, PayloadFilterSerializer
from .models import Action, ProbeSource


class ActionSerializer(serializers.ModelSerializer):
    http_post_kwargs = HTTPPostActionSerializer(
        source="get_http_post_kwargs", required=False, allow_null=True)
    slack_incoming_webhook_kwargs = SlackIncomingWebhookActionSerializer(
        source="get_slack_incoming_webhook_kwargs", required=False, allow_null=True)

    class Meta:
        model = Action
        fields = (
            "id",
            "backend",
            "name",
            "description",
            "http_post_kwargs",
            "slack_incoming_webhook_kwargs",
            "created_at",
            "updated_at",
        )

    def validate(self, data):
        data = super().validate(data)
        backend = data.get("backend")
        data["backend_kwargs"] = data.pop(f"get_{backend.lower()}_kwargs", None)
        if not data["backend_kwargs"]:
            raise serializers.ValidationError({f"{backend.lower()}_kwargs": "this field is required."})
        # cleanup other backend kwargs
        for k in list(data.keys()):
            if k.startswith("get_") and k.endswith("_kwargs"):
                data.pop(k)
        return data

    def create(self, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        action = super().create(validated_data)
        action.set_backend_kwargs(backend_kwargs)
        action.save()
        return action

    def update(self, instance, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        action = super().update(instance, validated_data)
        action.set_backend_kwargs(backend_kwargs)
        action.save()
        return action


class ProbeSourceSerializer(serializers.ModelSerializer):
    active = serializers.BooleanField(default=False)
    inventory_filters = serializers.ListField(child=InventoryFilterSerializer(), required=False)
    metadata_filters = serializers.ListField(child=MetadataFilterSerializer(), required=False)
    payload_filters = serializers.ListField(child=PayloadFilterSerializer(), required=False)
    incident_severity = serializers.ChoiceField(choices=Severity.choices(), required=False, allow_null=True)

    class Meta:
        model = ProbeSource
        fields = (
            "id",
            "name",
            "slug",
            "description",
            "inventory_filters",
            "metadata_filters",
            "payload_filters",
            "incident_severity",
            "actions",
            "active",
            "created_at",
            "updated_at",
        )

    def validate(self, data):
        data = super().validate(data)
        # active
        if data.pop("active", None):
            data["status"] = ProbeSource.ACTIVE
        else:
            data["status"] = ProbeSource.INACTIVE
        # slug
        slug_qs = ProbeSource.objects.filter(slug=slugify(data["name"]))
        if self.instance and self.instance.pk:
            slug_qs = slug_qs.exclude(pk=self.instance.pk)
        if slug_qs.exists():
            raise serializers.ValidationError(
                {"name": "this name produces a slug that is already taken by another probe source"}
            )
        # body
        data["body"] = body = {}
        # filters
        for filter_type in ("inventory", "metadata", "payload"):
            filters = data.pop(f"{filter_type}_filters", None)
            if not filters:
                continue
            body.setdefault("filters", {})[filter_type] = filters
        # incident severity
        incident_severity = data.pop("incident_severity", None)
        if incident_severity is not None:
            body["incident_severity"] = incident_severity
        return data
