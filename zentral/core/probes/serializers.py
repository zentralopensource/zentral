from rest_framework import serializers
from .action_backends.http import HTTPPostActionSerializer
from .action_backends.slack import SlackIncomingWebhookActionSerializer
from .models import Action


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
