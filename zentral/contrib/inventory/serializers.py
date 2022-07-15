from rest_framework import serializers
from .cleanup import get_default_snapshot_retention_days
from .models import EnrollmentSecret, MetaBusinessUnit, Tag, Taxonomy


# Machine mass tagging


class MachineTagsUpdatePrincipalUsers(serializers.Serializer):
    unique_ids = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False
    )
    principal_names = serializers.ListField(
        child=serializers.CharField(min_length=1),
        required=False
    )

    def validate(self, data):
        if not data.get("unique_ids") and not data.get("principal_names"):
            raise serializers.ValidationError("Unique ids and principal names cannot be both empty.")
        return data


class MachineTagsUpdateSerializer(serializers.Serializer):
    tags = serializers.DictField(child=serializers.CharField(allow_null=True), allow_empty=False)
    principal_users = MachineTagsUpdatePrincipalUsers()


# Archive or prune machines


class MachineSerialNumbersSerializer(serializers.Serializer):
    serial_numbers = serializers.ListField(
        child=serializers.CharField(min_length=1),
        min_length=1,
        max_length=1000
    )


# Cleanup inventory


class CleanupInventorySerializer(serializers.Serializer):
    days = serializers.IntegerField(min_value=1, max_value=3660, default=get_default_snapshot_retention_days)


# Standard model serializers


class MetaBusinessUnitSerializer(serializers.ModelSerializer):
    api_enrollment_enabled = serializers.BooleanField(required=False)

    class Meta:
        model = MetaBusinessUnit
        fields = ("id", "name", "api_enrollment_enabled", "created_at", "updated_at")
        read_only_fields = ("api_enrollment_enabled",)

    def validate_api_enrollment_enabled(self, value):
        if self.instance and self.instance.api_enrollment_enabled() and not value:
            raise serializers.ValidationError("Cannot disable API enrollment")
        return value

    def create(self, validated_data):
        api_enrollment_enabled = validated_data.pop("api_enrollment_enabled", False)
        mbu = super().create(validated_data)
        if api_enrollment_enabled:
            mbu.create_enrollment_business_unit()
        return mbu

    def update(self, instance, validated_data):
        api_enrollment_enabled = validated_data.pop("api_enrollment_enabled", False)
        mbu = super().update(instance, validated_data)
        if not mbu.api_enrollment_enabled() and api_enrollment_enabled:
            mbu.create_enrollment_business_unit()
        # TODO: switch off api_enrollment_enabled
        return mbu


class TagSerializer(serializers.ModelSerializer):
    class Meta:
        model = Tag
        fields = ("id", "taxonomy", "meta_business_unit", "name", "slug", "color")


class TaxonomySerializer(serializers.ModelSerializer):
    class Meta:
        model = Taxonomy
        fields = ("id", "meta_business_unit", "name", "created_at", "updated_at")


class EnrollmentSecretSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnrollmentSecret
        fields = ("id", "secret", "meta_business_unit", "tags", "serial_numbers", "udids", "quota", "request_count")
