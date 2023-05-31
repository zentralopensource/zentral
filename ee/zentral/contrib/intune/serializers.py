from rest_framework import serializers
from .models import Tenant


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = ("id", "business_unit", "name", "description",
                  "tenant_id", "client_id", "client_secret",
                  "version", "created_at", "updated_at")
