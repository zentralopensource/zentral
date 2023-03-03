from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Catalog, Condition, Enrollment, Manifest, ManifestCatalog, ManifestSubManifest, SubManifest


class CatalogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Catalog
        fields = '__all__'
        read_only_fields = ['archived_at']


class ConditionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Condition
        fields = '__all__'


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    configuration_profile_download_url = serializers.SerializerMethodField()
    plist_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        fields = ("id", "manifest",
                  "secret", "version",
                  "enrolled_machines_count",
                  "configuration_profile_download_url", "plist_download_url",
                  "created_at", "updated_at")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_download_url(self, fmt, obj):
        fqdn = settings["api"]["fqdn"]
        path = reverse(f"monolith_api:enrollment_{fmt}", args=(obj.pk,))
        return f'https://{fqdn}{path}'

    def get_configuration_profile_download_url(self, obj):
        return self.get_download_url("configuration_profile", obj)

    def get_plist_download_url(self, obj):
        return self.get_download_url("plist", obj)

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret_tags = secret_data.pop("tags", [])
        secret = EnrollmentSecret.objects.create(**secret_data)
        if secret_tags:
            secret.tags.set(secret_tags)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment

    def update(self, instance, validated_data):
        secret_serializer = self.fields["secret"]
        secret_data = validated_data.pop('secret')
        secret_serializer.update(instance.secret, secret_data)
        return super().update(instance, validated_data)


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
