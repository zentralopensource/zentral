from django.urls import reverse
from django.db.models import F
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.utils.os_version import make_comparable_os_version
from .compliance_checks import MunkiScriptCheck, validate_expected_result
from .models import Configuration, Enrollment, ScriptCheck


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        instance.refresh_from_db()
        return instance


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        exclude = ("distributor_content_type", "distributor_pk")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_package_download_url(self, obj):
        path = reverse("munki_api:enrollment_package", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

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


class ScriptCheckSerializer(serializers.ModelSerializer):
    name = serializers.CharField(source="compliance_check.name")
    description = serializers.CharField(
        source="compliance_check.description",
        allow_blank=True, required=False, default=""
    )
    version = serializers.IntegerField(source="compliance_check.version", read_only=True)

    class Meta:
        model = ScriptCheck
        fields = ("name", "description", "version",
                  "id", "tags", "excluded_tags",
                  "arch_amd64", "arch_arm64",
                  "min_os_version", "max_os_version",
                  "type", "source", "expected_result",
                  "created_at", "updated_at")

    def validate_name(self, value):
        qs = ComplianceCheck.objects.filter(model=MunkiScriptCheck.get_model(), name=value)
        if self.instance:
            qs = qs.exclude(pk=self.instance.compliance_check.pk)
        if qs.count():
            raise serializers.ValidationError(
                f"A {MunkiScriptCheck.model_display} with this name already exists."
            )
        return value

    def validate(self, data):
        # expected result type
        script_check_type = data.get("type")
        expected_result = data.get("expected_result")
        if script_check_type and expected_result:
            expected_result_valid, error_message = validate_expected_result(script_check_type, expected_result)
            if not expected_result_valid:
                raise serializers.ValidationError({"expected_result": error_message})
        # at least one arch
        arch_amd64 = data.get("arch_amd64", True)
        arch_arm64 = data.get("arch_arm64", True)
        if not arch_amd64 and not arch_arm64:
            msg = "This check has to run on at least one architecture"
            raise serializers.ValidationError({"arch_amd64": msg,
                                               "arch_arm64": msg})
        # disjoint tag sets
        tags = set(data.get("tags", []))
        excluded_tags = set(data.get("excluded_tags", []))
        if tags & excluded_tags:
            raise serializers.ValidationError("tags and excluded tags must be disjoint")
        # min / max OS versions
        min_os_version = data.get("min_os_version")
        comparable_min_os_version = None
        if min_os_version:
            comparable_min_os_version = make_comparable_os_version(min_os_version)
            if comparable_min_os_version == (0, 0, 0):
                raise serializers.ValidationError({"min_os_version": "Not a valid OS version"})
        max_os_version = data.get("max_os_version")
        comparable_max_os_version = None
        if max_os_version:
            comparable_max_os_version = make_comparable_os_version(max_os_version)
            if comparable_max_os_version == (0, 0, 0):
                raise serializers.ValidationError({"max_os_version": "Not a valid OS version"})
        if (
            comparable_min_os_version
            and comparable_max_os_version
            and comparable_max_os_version > (0, 0, 0)
            and comparable_min_os_version > comparable_max_os_version
        ):
            raise serializers.ValidationError({"min_os_version": "Should be smaller than the max OS version"})
        return data

    def create(self, validated_data):
        cc_data = validated_data.pop("compliance_check")
        compliance_check = ComplianceCheck.objects.create(
            model=MunkiScriptCheck.get_model(),
            name=cc_data.get("name"),
            description=cc_data.get("description") or "",
        )
        tags = validated_data.pop("tags", [])
        excluded_tags = validated_data.pop("excluded_tags", [])
        script_check = ScriptCheck.objects.create(
            compliance_check=compliance_check,
            **validated_data,
        )
        script_check.tags.set(tags)
        script_check.excluded_tags.set(excluded_tags)
        return script_check

    def update(self, instance, validated_data):
        # compliance check
        compliance_check = instance.compliance_check
        cc_data = validated_data.pop("compliance_check")
        compliance_check.name = cc_data.get("name")
        compliance_check.description = cc_data.get("description") or ""
        # script check
        script_check_updated = False
        tags = sorted(validated_data.pop("tags", []), key=lambda t: t.pk)
        excluded_tags = sorted(validated_data.pop("excluded_tags", []), key=lambda t: t.pk)
        for key, value in validated_data.items():
            old_value = getattr(instance, key)
            if value != old_value:
                script_check_updated = True
            setattr(instance, key, value)
        if sorted(instance.tags.all(), key=lambda t: t.pk) != tags:
            script_check_updated = True
        if sorted(instance.excluded_tags.all(), key=lambda t: t.pk) != tags:
            script_check_updated = True
        if script_check_updated:
            compliance_check.version = F("version") + 1
        compliance_check.save()
        if script_check_updated:
            # to materialize the updated version
            compliance_check.refresh_from_db()
        instance.save()
        instance.tags.set(tags)
        instance.excluded_tags.set(excluded_tags)
        return instance
