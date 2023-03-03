from rest_framework import serializers
from .models import Catalog, Condition, Manifest, ManifestCatalog, ManifestSubManifest, SubManifest


class CatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catalog
        fields = '__all__'
        read_only_fields = ['archived_at']


class ConditionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Condition
        fields = '__all__'


class ManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = Manifest
        fields = '__all__'


class ManifestCatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ManifestCatalog
        fields = '__all__'


class ManifestSubManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ManifestSubManifest
        fields = '__all__'


class SubManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubManifest
        fields = '__all__'
