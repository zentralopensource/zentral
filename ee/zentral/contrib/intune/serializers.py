from rest_framework import serializers
from .models import Tenant


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['client_secret'] = instance.get_client_secret()
        return data
