from rest_framework import serializers

from .models import Tenant


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tenant
        fields = '__all__'

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if instance.client_secret:
            data['client_secret'] = instance.get_client_secret()
        return data

    def create(self, validated_data):
        tenant = Tenant.objects.create(**validated_data)
        tenant.set_client_secret(validated_data['client_secret'])
        tenant.save()
        tenant.refresh_from_db()
        return tenant

    def update(self, instance, validated_data):
        instance.set_client_secret(validated_data['client_secret'])
        validated_data['client_secret'] = instance.client_secret
        instance = super().update(instance, validated_data)
        instance.refresh_from_db()
        return instance
