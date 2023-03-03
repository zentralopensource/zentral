from rest_framework import serializers
from .models import Catalog, Manifest, ManifestCatalog


class CatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catalog
        fields = '__all__'
        read_only_fields = ['archived_at']


class ManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manifest
        fields = '__all__'


class ManifestCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ManifestCatalog
        fields = '__all__'
