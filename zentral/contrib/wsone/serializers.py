from rest_framework import serializers
from .models import Instance


class InstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Instance
        fields = ("id", "business_unit", "client_id", "server_url",
                  "excluded_groups", "version", "created_at", "updated_at")
