from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .compliance_checks import sync_mscp_check_compliance_check, sync_script_compliance_check
from .models import Configuration, Enrollment, MSCPCheck, OneTimeJob, RecurringJob, Script


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    configuration_profile_download_url = serializers.SerializerMethodField()
    plist_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        fields = ("id", "configuration", "secret", "version",
                  "enrolled_machines_count",
                  "configuration_profile_download_url", "plist_download_url",
                  "created_at", "updated_at")

    def get_enrolled_machines_count(self, obj):
        # the list/detail querysets annotate this; fall back to a count for freshly created/updated instances
        count = getattr(obj, "enrolled_machines_count", None)
        if count is None:
            count = obj.enrolledmachine_set.count()
        return count

    def get_artifact_download_url(self, view_name, obj):
        path = reverse(f"turbo_api:{view_name}", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

    def get_configuration_profile_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_configuration_profile", obj)

    def get_plist_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_plist", obj)

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


class ScriptSerializer(serializers.ModelSerializer):
    version = serializers.IntegerField(source="job.version", read_only=True)
    compliance_check_enabled = serializers.BooleanField(default=False)
    compliance_check_id = serializers.IntegerField(read_only=True, allow_null=True)

    class Meta:
        model = Script
        fields = ("id", "name", "description", "source", "tag",
                  "arch_amd64", "arch_arm64", "min_os_version", "max_os_version",
                  "version", "compliance_check_enabled", "compliance_check_id",
                  "created_at", "updated_at")

    def create(self, validated_data):
        compliance_check_enabled = validated_data.pop("compliance_check_enabled")
        script = Script.objects.create(**validated_data)   # mints the Job
        sync_script_compliance_check(script, compliance_check_enabled)
        return script

    def update(self, instance, validated_data):
        compliance_check_enabled = validated_data.pop("compliance_check_enabled")
        source = validated_data.get("source")
        bump = source is not None and source != instance.source   # version lives on the Job
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if bump:
            instance.job.bump_version()
        sync_script_compliance_check(instance, compliance_check_enabled)
        return instance


class MSCPCheckSerializer(serializers.ModelSerializer):
    version = serializers.IntegerField(source="job.version", read_only=True)
    compliance_check_id = serializers.IntegerField(read_only=True)
    # blank=True alone keeps a CharField required in DRF (unlike Django forms); default "" makes it optional
    baseline = serializers.CharField(max_length=64, required=False, allow_blank=True, default="")

    class Meta:
        model = MSCPCheck
        fields = ("id", "rule_id", "baseline", "odv_int", "odv_string", "odv_bool",
                  "version", "compliance_check_id", "created_at", "updated_at")

    def validate_odv_string(self, value):
        # an empty override is no override (defer to the baseline default), not the empty string
        return value or None

    def validate(self, data):
        def effective(field):
            return data[field] if field in data else getattr(self.instance, field, None)
        set_odvs = [f for f in ("odv_int", "odv_string", "odv_bool") if effective(f) is not None]
        if len(set_odvs) > 1:
            raise serializers.ValidationError("Set at most one ODV override")
        if set_odvs and effective("baseline"):
            raise serializers.ValidationError("Set a baseline or an ODV override, not both")
        return data

    def create(self, validated_data):
        return MSCPCheck.objects.create(**validated_data)   # mints the Job + the compliance check

    def update(self, instance, validated_data):
        # every MSCPCheck field is identity-bearing, so any change bumps the Job version
        bump = any(getattr(instance, attr) != value for attr, value in validated_data.items())
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if bump:
            instance.job.bump_version()
        sync_mscp_check_compliance_check(instance)
        return instance


class JobScopeSerializerMixin:
    def _scope_conflicts(self, data):
        def current(field, many):
            if field in data:
                return set(data[field])
            if self.instance is not None:
                value = getattr(self.instance, field)
                return set(value.all() if many else value)
            return set()
        errors = {}
        if current("tags", True) & current("excluded_tags", True):
            errors["excluded_tags"] = "Tags and excluded tags must be disjoint"
        if current("serial_numbers", False) & current("excluded_serial_numbers", False):
            errors["excluded_serial_numbers"] = "Serial numbers and excluded serial numbers must be disjoint"
        return errors

    def validate(self, data):
        data = super().validate(data)
        errors = self._scope_conflicts(data)
        if errors:
            raise serializers.ValidationError(errors)
        return data


class RecurringJobSerializer(JobScopeSerializerMixin, serializers.ModelSerializer):
    # ArrayField isn't auto-mapped by ModelSerializer; declare the serial lists explicitly (see santa)
    serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1), required=False)
    excluded_serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1), required=False)

    class Meta:
        model = RecurringJob
        fields = ("id", "configuration", "job", "interval",
                  "tags", "excluded_tags", "serial_numbers", "excluded_serial_numbers",
                  "created_at", "updated_at")


class OneTimeJobSerializer(JobScopeSerializerMixin, serializers.ModelSerializer):
    serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1), required=False)
    excluded_serial_numbers = serializers.ListField(child=serializers.CharField(min_length=1), required=False)

    class Meta:
        model = OneTimeJob
        fields = ("id", "configuration", "job", "not_before", "not_after",
                  "tags", "excluded_tags", "serial_numbers", "excluded_serial_numbers",
                  "created_at", "updated_at")

    def validate(self, data):
        data = super().validate(data)
        not_before = data["not_before"] if "not_before" in data else getattr(self.instance, "not_before", None)
        not_after = data["not_after"] if "not_after" in data else getattr(self.instance, "not_after", None)
        if not_before and not_after and not_before > not_after:
            raise serializers.ValidationError({"not_after": "not_after must be on or after not_before"})
        return data
