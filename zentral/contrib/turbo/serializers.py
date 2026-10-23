from django.urls import reverse
from rest_framework import serializers

from zentral.conf import api_base_url
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.utils.drf import FullUpdateSerializerMixin

from .command_backends import get_command_backend_class
from .compliance_checks import sync_mscp_check_compliance_check, sync_script_compliance_check
from .models import (Configuration, Enrollment, FileExport, Job, JobUpload, MSCPCheck, OneTimeJob,
                     OneTimeJobMachine, RecurringJob, RecurringJobMachine, ScheduleMode, Script, Sysdiagnose,
                     UploadStatus)


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = "__all__"


class EnrollmentInfoSerializer(serializers.ModelSerializer):
    """Slim public-facing enrollment, returned to the agent by the enrollment-info endpoint."""
    class Meta:
        model = Enrollment
        fields = ("pk", "version")
        read_only_fields = ("pk", "version")


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
        return f"{api_base_url()}{path}"

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
    job_id = serializers.UUIDField(read_only=True)
    # declared with the model default so they are always in validated_data — validate() can then check
    # them without special-casing "omitted on create"
    arch_amd64 = serializers.BooleanField(default=True)
    arch_arm64 = serializers.BooleanField(default=True)
    compliance_check_enabled = serializers.BooleanField(default=False)
    compliance_check_id = serializers.IntegerField(read_only=True, allow_null=True)

    class Meta:
        model = Script
        fields = ("id", "name", "description", "source", "tag",
                  "arch_amd64", "arch_arm64", "min_os_version", "max_os_version",
                  "version", "job_id", "compliance_check_enabled", "compliance_check_id",
                  "created_at", "updated_at")

    def validate(self, data):
        # compatibility gate: a script that runs on neither architecture never runs anywhere, so the
        # agent would silently skip it — the UI ScriptForm rejects this too
        if not data["arch_amd64"] and not data["arch_arm64"]:
            raise serializers.ValidationError("Select at least one architecture")
        return data

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
    job_id = serializers.UUIDField(read_only=True)
    # blank=True alone keeps a CharField required in DRF (unlike Django forms); default "" makes it optional
    baseline = serializers.CharField(max_length=64, required=False, allow_blank=True, default="")

    class Meta:
        model = MSCPCheck
        fields = ("id", "rule_id", "baseline", "odv_int", "odv_string", "odv_bool",
                  "version", "job_id", "compliance_check_id", "created_at", "updated_at")

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


class CommandKindSerializer(serializers.ModelSerializer):
    # A subclass sets Meta.model to the proxy model of a kind.
    version = serializers.IntegerField(source="job.version", read_only=True)
    job_id = serializers.UUIDField(read_only=True)

    class Meta:
        fields = ("id", "name", "description", "version", "job_id", "created_at", "updated_at")

    def get_fields(self):
        # The options of the kind are top-level fields, like the fields of a script. The backend
        # declares them once, for the API and the console. The kwargs of a kind are never
        # encrypted, because the agent gets them, so the field reads the stored value.
        backend_class = get_command_backend_class(self.Meta.model.command_backend)
        option_fields = backend_class.kwargs_serializer().get_fields()
        fields = {}
        for name, field in super().get_fields().items():
            fields[name] = field
            if name == "description":
                for option_name, option_field in option_fields.items():
                    option_field.source = f"backend_kwargs.{option_name}"
                    fields[option_name] = option_field
        return fields

    def validate_name(self, value):
        # unique for each kind, not in the shared table
        model = self.Meta.model
        qs = model.objects.filter(name=value)
        if self.instance is not None:
            qs = qs.exclude(pk=self.instance.pk)
        if qs.exists():
            raise serializers.ValidationError(f"{model._meta.verbose_name} with this name already exists.")
        return value

    def create(self, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        instance = self.Meta.model.objects.create(**validated_data)  # mints the Job, with the kind
        instance.set_backend_kwargs(backend_kwargs)
        instance.save()
        return instance

    def update(self, instance, validated_data):
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        # The version is on the Job. It changes only when the work of the agent changes. A machine
        # that has not reported a result yet gets the new version. A new name or description does
        # not change it.
        bump = backend_kwargs != instance.get_backend_kwargs()
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.set_backend_kwargs(backend_kwargs)
        instance.save()
        if bump:
            instance.job.bump_version()
        return instance


class SysdiagnoseSerializer(CommandKindSerializer):
    class Meta(CommandKindSerializer.Meta):
        model = Sysdiagnose


class FileExportSerializer(CommandKindSerializer):
    class Meta(CommandKindSerializer.Meta):
        model = FileExport


class JobScopeResourceSerializer(serializers.Serializer):
    """Reads the configuration of a create body, and nothing else.

    The configuration is the resource of the create preview, which is decided before the validation of
    the body.
    """
    configuration = serializers.PrimaryKeyRelatedField(queryset=Configuration.objects.all())


class JobScopeSerializerMixin:
    # The checks read the body only, never the stored schedule: a create has nothing stored, and a PUT
    # carries every field (FullUpdateSerializerMixin).

    def _scope_conflicts(self, data):
        def current(field):
            return set(data.get(field, ()))
        errors = {}
        if current("tags") & current("excluded_tags"):
            errors["excluded_tags"] = "Tags and excluded tags must be disjoint"
        if current("serial_numbers") & current("excluded_serial_numbers"):
            errors["excluded_serial_numbers"] = "Serial numbers and excluded serial numbers must be disjoint"
        return errors

    def validate(self, data):
        data = super().validate(data)
        # what a schedule delivers, and where, is fixed at creation (the UI pins both): re-pointing it
        # would retarget another configuration's whole fleet, or strand its per-machine ledger rows
        for field in ("configuration", "job"):
            if self.instance is not None and data[field] != getattr(self.instance, field):
                raise serializers.ValidationError({field: "This field cannot be changed"})
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

    def validate(self, data):
        data = super().validate(data)
        # A kind for the one-time mode only cannot use a recurring schedule. The console removes
        # it from the choices. The API must give the error.
        job = data["job"]
        if ScheduleMode.RECURRING not in Job.allowed_schedule_modes(job.kind):
            raise serializers.ValidationError(
                {"job": f"A {job.get_kind_display().lower()} job cannot be scheduled to run repeatedly"})
        return data


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
        not_before = data.get("not_before")
        not_after = data.get("not_after")
        if not_before and not_after and not_before > not_after:
            raise serializers.ValidationError({"not_after": "not_after must be on or after not_before"})
        return data


class RecurringJobUpdateSerializer(FullUpdateSerializerMixin, RecurringJobSerializer):
    pass


class OneTimeJobUpdateSerializer(FullUpdateSerializerMixin, OneTimeJobSerializer):
    pass


class ArtifactSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()

    class Meta:
        model = JobUpload
        fields = ("id", "run_id", "artifact", "mode", "size", "sha256", "truncated", "attempts", "status",
                  "error_reason", "verification", "created_at", "updated_at", "completed_at", "verified_at",
                  "download_url")

    def get_download_url(self, obj):
        # null when there is no file, or when the caller cannot download it
        if obj.status != UploadStatus.UPLOADED or not obj.can_download:
            return None
        return f"{api_base_url()}{reverse('turbo_api:artifact_download', args=(obj.pk,))}"


class OneTimeJobMachineSerializer(serializers.ModelSerializer):
    artifacts = ArtifactSerializer(many=True, read_only=True)

    class Meta:
        model = OneTimeJobMachine
        fields = ("serial_number", "seen_version", "last_result_version", "first_seen_at", "last_seen_at",
                  "first_result_at", "last_result_at", "removed_at", "artifacts")


class RecurringJobMachineSerializer(serializers.ModelSerializer):
    class Meta:
        model = RecurringJobMachine
        fields = ("serial_number", "seen_version", "seen_interval", "last_result_version", "first_seen_at",
                  "last_seen_at", "first_result_at", "last_result_at", "removed_at")
