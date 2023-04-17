from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import (Catalog, Condition, Enrollment, Manifest, ManifestCatalog, ManifestSubManifest,
                     PkgInfoName, SubManifest, SubManifestPkgInfo)


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

    def validate(self, data):
        manifest_mbu = data["manifest"].meta_business_unit
        secret_mbu = data["secret"]["meta_business_unit"]
        if manifest_mbu != secret_mbu:
            raise serializers.ValidationError({
                "secret.meta_business_unit": "Must be the same as the manifest meta business unit."
            })
        return data

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
        extra_kwargs = {
            # the tags field is required, but allowed to be empty
            "tags": {"allow_empty": True}
        }


class ManifestSubManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = ManifestSubManifest
        fields = '__all__'
        extra_kwargs = {
            # the tags field is required, but allowed to be empty
            "tags": {"allow_empty": True}
        }


class SubManifestSerializer(serializers.ModelSerializer):
    class Meta:
        model = SubManifest
        fields = '__all__'


class SubManifestPkgInfoTagSerializer(serializers.Serializer):
    tag = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all())
    shard = serializers.IntegerField(min_value=1, max_value=100)


class SubManifestPkgInfoSerializer(serializers.ModelSerializer):
    pkg_info_name = serializers.CharField(allow_blank=False)
    shard_modulo = serializers.IntegerField(min_value=2, max_value=100, default=100)
    default_shard = serializers.IntegerField(min_value=0, max_value=100, default=100)
    excluded_tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True)
    tag_shards = SubManifestPkgInfoTagSerializer(many=True)

    class Meta:
        model = SubManifestPkgInfo
        fields = (
            "id",
            "sub_manifest", "key",
            "featured_item",
            "condition",
            "pkg_info_name",
            "shard_modulo",
            "default_shard",
            "excluded_tags",
            "tag_shards",
            "created_at", "updated_at"
        )

    def validate_pkg_info_name(self, value):
        try:
            return PkgInfoName.objects.get(name=value)
        except PkgInfoName.DoesNotExist:
            raise serializers.ValidationError("Unknown PkgInfo name")

    def validate(self, data):
        default_shard = data.pop("default_shard")
        shard_modulo = data.pop("shard_modulo")

        errors = {}

        # default_shard <= shard_modulo
        if default_shard > shard_modulo:
            errors["default_shard"] = ["cannot be greater than shard_modulo"]

        excluded_tags = data.pop("excluded_tags")
        tag_shards = data.pop("tag_shards")
        seen_tags = set()
        for tag_shard in tag_shards:
            tag = tag_shard["tag"]
            # tags unique
            if tag in seen_tags:
                tags_errors = errors.setdefault("tag_shards", [])
                error = f"{tag.id}: duplicated"
                if error not in tags_errors:
                    tags_errors.append(error)
            # tags not in excluded_tags
            if tag in excluded_tags:
                errors.setdefault("tag_shards", []).append(f"{tag.id}: cannot be excluded")
            # tag shards <= shard_modulo
            if tag_shard["shard"] > shard_modulo:
                errors.setdefault("tag_shards", []).append(f"{tag.id}: shard > shard_modulo")
            seen_tags.add(tag)

        if errors:
            raise serializers.ValidationError(errors)

        options = {}
        if data["key"] in ("default_installs", "managed_installs", "optional_installs"):
            if excluded_tags:
                options["excluded_tags"] = [t.name for t in excluded_tags]
            options["shards"] = {
                "default": default_shard,
                "modulo": shard_modulo,
            }
            tag_shards = {ts["tag"].name: ts["shard"] for ts in tag_shards}
            if tag_shards:
                options["shards"]["tags"] = tag_shards
        data["options"] = options

        return data
