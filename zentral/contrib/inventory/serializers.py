from django.db.models import F
from rest_framework import serializers
from zentral.core.compliance_checks.models import ComplianceCheck
from .utils import get_default_snapshot_retention_days
from .compliance_checks import InventoryJMESPathCheck
from .models import EnrollmentSecret, JMESPathCheck, MetaBusinessUnit, Tag, Taxonomy


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


class MachineTagOperation(serializers.Serializer):
    kind = serializers.ChoiceField(choices=(("SET", "Set"), ("ADD", "Add"), ("REMOVE", "Remove")), required=True)
    taxonomy = serializers.CharField(max_length=256, allow_blank=False, allow_null=True, required=False)
    names = serializers.ListField(child=serializers.CharField(max_length=50),
                                  allow_empty=True, required=True)

    def validate(self, data):
        data = super().validate(data)
        kind = data["kind"]
        taxonomy = data.get("taxonomy")
        names = data.get("names")
        if kind == "SET":
            if not taxonomy:
                raise serializers.ValidationError({"taxonomy": "This field is required for SET operations"})
        elif kind == "REMOVE":
            if taxonomy:
                raise serializers.ValidationError({"taxonomy": "This field may not be set for REMOVE operations"})
            if not names:
                raise serializers.ValidationError({"names": "This list may not be empty for REMOVE operations"})
        elif kind == "ADD":
            if not names:
                raise serializers.ValidationError({"names": "This list may not be empty for ADD operations"})
        return data


class MachineTagsUpdateSerializer(serializers.Serializer):
    principal_users = MachineTagsUpdatePrincipalUsers(required=False)
    serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1),
                                           allow_empty=False, required=False)
    operations = serializers.ListField(child=MachineTagOperation(),
                                       allow_empty=False, required=True)

    def validate(self, data):
        data = super().validate(data)
        if not data.get("principal_users") and not data.get("serial_numbers"):
            raise serializers.ValidationError("principal_users and serial_numbers cannot be both empty.")
        return data


# MetaMachine


class MetaMachineSerializer(serializers.Serializer):
    serial_number = serializers.CharField()
    urlsafe_serial_number = serializers.CharField(source="get_urlsafe_serial_number")
    computer_name = serializers.CharField()
    platform = serializers.CharField()
    type = serializers.CharField()
    tags = serializers.SerializerMethodField()

    def get_tags(self, obj):
        return [{"id": pk, "name": name} for pk, name in obj.tag_pks_and_names]


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


class JMESPathCheckSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source="compliance_check.name")
    description = serializers.CharField(
        source="compliance_check.description",
        allow_blank=True, required=False, default=""
    )
    version = serializers.IntegerField(source="compliance_check.version", read_only=True)

    class Meta:
        model = JMESPathCheck
        fields = ("name", "description", "version",
                  "id", "source_name", "platforms", "tags",
                  "jmespath_expression", "created_at", "updated_at")

    def validate_name(self, value):
        qs = ComplianceCheck.objects.filter(model=InventoryJMESPathCheck.get_model(), name=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.compliance_check.pk)
        if qs.count():
            raise serializers.ValidationError(
                f"A {InventoryJMESPathCheck.model_display} with this name already exists."
            )
        return value

    def create(self, validated_data):
        cc_data = validated_data.pop("compliance_check")
        compliance_check = ComplianceCheck.objects.create(
            model=InventoryJMESPathCheck.get_model(),
            name=cc_data.get("name"),
            description=cc_data.get("description") or "",
        )
        tags = validated_data.pop("tags")
        jmespath_check = JMESPathCheck.objects.create(
            compliance_check=compliance_check,
            **validated_data,
        )
        jmespath_check.tags.set(tags)
        return jmespath_check

    def update(self, instance, validated_data):
        # compliance check
        compliance_check = instance.compliance_check
        cc_data = validated_data.pop("compliance_check")
        compliance_check.name = cc_data.get("name")
        compliance_check.description = cc_data.get("description") or ""
        # JMESPath check
        jmespath_check_updated = False
        tags = sorted(validated_data.pop("tags", []), key=lambda t: t.pk)
        for key, value in validated_data.items():
            old_value = getattr(instance, key)
            if value != old_value:
                jmespath_check_updated = True
            setattr(instance, key, value)
        if sorted(instance.tags.all(), key=lambda t: t.pk) != tags:
            jmespath_check_updated = True
        if jmespath_check_updated:
            compliance_check.version = F("version") + 1
        compliance_check.save()
        if jmespath_check_updated:
            # to materialize the updated version
            compliance_check.refresh_from_db()
        instance.save()
        instance.tags.set(tags)
        return instance


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
