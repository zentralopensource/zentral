from rest_framework import serializers
from .models import Catalog, Manifest


class CatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catalog
        fields = '__all__'
        read_only_fields = ['archived_at']


class ManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manifest
        fields = '__all__'
