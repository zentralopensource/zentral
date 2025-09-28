import base64
import logging
import os
import plistlib
import uuid
import zipfile
from django.core.files import File
from django.db import transaction
from rest_framework import serializers
from zentral.contrib.inventory.models import EnrollmentSecret, Tag
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from zentral.utils.external_resources import download_external_resource
from zentral.utils.os_version import make_comparable_os_version
from zentral.utils.ssl import ensure_bytes
from .app_manifest import read_package_info, validate_configuration
from .artifacts import Target, update_blueprint_serialized_artifacts
from .cert_issuer_backends import CertIssuerBackend
from .cert_issuer_backends.ident import IDentSerializer
from .cert_issuer_backends.microsoft_ca import MicrosoftCASerializer
from .cert_issuer_backends.okta_ca import OktaCASerializer
from .cert_issuer_backends.static_challenge import StaticChallengeSerializer
from .crypto import generate_push_certificate_key_bytes, load_push_certificate_and_key
from .declarations import verify_declaration_source
from .dep import assign_dep_device_profile, DEPClientError
from .events import post_admin_password_viewed_event
from .models import (ACMEIssuer,
                     Artifact, ArtifactVersion, ArtifactVersionTag,
                     Blueprint, BlueprintArtifact, BlueprintArtifactTag,
                     DEPDevice, DEPEnrollment,
                     DataAsset,
                     Declaration, DeclarationRef,
                     DeviceCommand,
                     EnrolledDevice, EnrolledUser,
                     EnterpriseApp, FileVaultConfig,
                     Location, LocationAsset,
                     OTAEnrollment,
                     Platform, Profile, PushCertificate,
                     RecoveryPasswordConfig,
                     SCEPIssuer,
                     SoftwareUpdateEnforcement,
                     UserCommand)
from .payloads import get_configuration_profile_info


logger = logging.getLogger("zentral.contrib.mdm.serializers")


class DeviceCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeviceCommand
        fields = (
            "uuid",
            "enrolled_device",
            "name",
            "artifact_version",
            "artifact_operation",
            "not_before",
            "time",
            "result",
            "result_time",
            "status",
            "error_chain",
            "created_at",
            "updated_at"
        )


class UserCommandSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserCommand
        fields = (
            "uuid",
            "enrolled_user",
            "name",
            "artifact_version",
            "artifact_operation",
            "not_before",
            "time",
            "result",
            "result_time",
            "status",
            "error_chain",
            "created_at",
            "updated_at"
        )


class EnrolledUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnrolledUser
        fields = (
            "id",
            "user_id",
            "enrollment_id",
            "long_name",
            "short_name",
            "declarative_management",
            "last_ip",
            "last_seen_at",
            "created_at",
            "updated_at",
        )


class EnrolledDeviceSerializer(serializers.ModelSerializer):
    os_version = serializers.CharField(source="current_os_version")
    build_version = serializers.CharField(source="current_build_version")
    users = EnrolledUserSerializer(many=True)

    class Meta:
        model = EnrolledDevice
        fields = (
            "id",
            "users",
            "udid",
            "serial_number",
            "name",
            "model",
            "platform",
            "os_version",
            "build_version",
            "apple_silicon",
            "cert_not_valid_after",
            "cert_att_serial_number",
            "cert_att_udid",
            "blueprint",
            "awaiting_configuration",
            "declarative_management",
            "dep_enrollment",
            "user_enrollment",
            "user_approved_enrollment",
            "supervised",
            "bootstrap_token_escrowed",
            "filevault_enabled",
            "filevault_prk_escrowed",
            "recovery_password_escrowed",
            "admin_guid",
            "admin_shortname",
            "admin_password_escrowed",
            "activation_lock_manageable",
            "last_ip",
            "last_seen_at",
            "last_notified_at",
            "checkout_at",
            "blocked_at",
            "created_at",
            "updated_at",
        )


class EnrolledDeviceAdminPasswordSerializer(serializers.ModelSerializer):
    admin_password = serializers.CharField(source="get_admin_password")

    class Meta:
        model = EnrolledDevice
        fields = ("id", "serial_number", "admin_password")
        read_only_fields = ("id", "serial_number", "admin_password")

    def to_representation(self, instance):
        r = super().to_representation(instance)
        if r.get("admin_password"):
            post_admin_password_viewed_event(self.context['request'], instance)
            if (
                instance.admin_guid
                and isinstance(instance.current_enrollment, DEPEnrollment)
                and instance.current_enrollment.admin_password_rotation_delay
            ):
                from .commands import SetAutoAdminPassword
                SetAutoAdminPassword.create_for_auto_rotation(
                    Target(instance),
                    instance.current_enrollment.admin_password_rotation_delay
                )
        return r


class ArtifactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Artifact
        fields = "__all__"

    def update(self, instance, validated_data):
        with transaction.atomic(durable=True):
            instance = super().update(instance, validated_data)
        with transaction.atomic(durable=True):
            for blueprint in instance.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return instance


class FileVaultConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileVaultConfig
        fields = "__all__"

    def validate(self, data):
        bypass_attempts = data.get("bypass_attempts", -1)
        if data.get("at_login_only", False):
            if bypass_attempts < 0:
                raise serializers.ValidationError({"bypass_attempts": "Must be >= 0 when at_login_only is True"})
        elif bypass_attempts > -1:
            raise serializers.ValidationError({"bypass_attempts": "Must be -1 when at_login_only is False"})
        return data


class DEPDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = DEPDevice
        fields = [
            "id",
            "virtual_server", "serial_number",
            "asset_tag", "color",
            "description", "device_family",
            "model", "os",
            "device_assigned_by", "device_assigned_date",
            "last_op_type", "last_op_date",
            "profile_status", "profile_uuid", "profile_assign_time", "profile_push_time",
            "enrollment",
            "disowned_at", "created_at", "updated_at",
        ]
        read_only_fields = [
            "id",
            "virtual_server", "serial_number",
            "asset_tag", "color",
            "description", "device_family",
            "model", "os",
            "device_assigned_by", "device_assigned_date",
            "last_op_type", "last_op_date",
            "profile_status", "profile_uuid", "profile_assign_time", "profile_push_time",
            "disowned_at", "created_at", "updated_at",
        ]

    def update(self, instance, validated_data):
        enrollment = validated_data.pop("enrollment")
        try:
            assign_dep_device_profile(instance, enrollment)
        except DEPClientError:
            logger.exception("Could not assign enrollment to device")
            raise serializers.ValidationError({"enrollment": "Could not assign enrollment to device"})
        else:
            instance.enrollment = enrollment
        return super().update(instance, validated_data)


class OTAEnrollmentSerializer(serializers.ModelSerializer):
    enrollment_secret = EnrollmentSecretSerializer(many=False)

    class Meta:
        model = OTAEnrollment
        fields = "__all__"

    def create(self, validated_data):
        secret_data = validated_data.pop('enrollment_secret')
        secret_tags = secret_data.pop("tags", [])
        secret = EnrollmentSecret.objects.create(**secret_data)
        if secret_tags:
            secret.tags.set(secret_tags)
        return OTAEnrollment.objects.create(enrollment_secret=secret, **validated_data)

    def update(self, instance, validated_data):
        secret_serializer = self.fields["enrollment_secret"]
        secret_data = validated_data.pop('enrollment_secret')
        secret_serializer.update(instance.enrollment_secret, secret_data)
        return super().update(instance, validated_data)


class PushCertificateSerializer(serializers.ModelSerializer):
    class Meta:
        model = PushCertificate
        fields = (
            "id",
            "provisioning_uid",
            "name",
            "topic",
            "not_before",
            "not_after",
            "certificate",
            "created_at",
            "updated_at"
        )

    def to_internal_value(self, data):
        # We need to implement this to keep the certificate
        # and apply it only if it is provided in the uploaded data.
        # There is no reason to nullify the certificate!
        certificate = data.pop("certificate", None)
        data = super().to_internal_value(data)
        if certificate:
            data["certificate"] = certificate
        return data

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.certificate:
            ret["certificate"] = ensure_bytes(instance.certificate).decode("ascii")
        return ret

    def validate(self, data):
        certificate = data.pop("certificate", None)
        if certificate:
            if not self.instance:
                raise serializers.ValidationError("Certificate cannot be set when creating a push certificate")
            try:
                push_certificate_d = load_push_certificate_and_key(
                    certificate,
                    self.instance.get_private_key(),
                )
            except ValueError as e:
                raise serializers.ValidationError(str(e))
            if self.instance.topic:
                if push_certificate_d["topic"] != self.instance.topic:
                    raise serializers.ValidationError("The new certificate has a different topic")
            else:
                if PushCertificate.objects.filter(topic=push_certificate_d["topic"]).exists():
                    raise serializers.ValidationError("A different certificate with the same topic already exists")
            push_certificate_d.pop("private_key")
            data.update(push_certificate_d)
        return data

    def create(self, validated_data):
        instance = super().create(validated_data)
        instance.set_private_key(generate_push_certificate_key_bytes())
        instance.save()
        return instance


class RecoveryPasswordConfigSerializer(serializers.ModelSerializer):
    static_password = serializers.CharField(required=False, source="get_static_password", allow_null=True)

    class Meta:
        model = RecoveryPasswordConfig
        fields = ("id", "name",
                  "dynamic_password", "static_password",
                  "rotation_interval_days", "rotate_firmware_password",
                  "created_at", "updated_at")

    def validate(self, data):
        dynamic_password = data.get("dynamic_password", True)
        static_password = data.get("get_static_password")
        rotation_interval_days = data.get("rotation_interval_days")
        rotate_firmware_password = data.get("rotate_firmware_password")
        errors = {}
        if dynamic_password:
            if static_password:
                errors["static_password"] = "Cannot be set when dynamic_password is true"
        else:
            if not static_password:
                errors["static_password"] = "Required when dynamic_password is false"
            if rotation_interval_days:
                errors["rotation_interval_days"] = "Cannot be set with a static password"
            if rotate_firmware_password:
                errors["rotate_firmware_password"] = "Cannot be set with a static password"
        if rotate_firmware_password and not rotation_interval_days:
            errors["rotate_firmware_password"] = "Cannot be set without a rotation interval"
        if errors:
            raise serializers.ValidationError(errors)
        return data

    def create(self, validated_data):
        static_password = validated_data.pop("get_static_password", None)
        instance = RecoveryPasswordConfig.objects.create(**validated_data)
        if static_password:
            instance.set_static_password(static_password)
            instance.save()
        return instance

    def update(self, instance, validated_data):
        static_password = validated_data.pop("get_static_password", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.set_static_password(static_password)
        instance.save()
        return instance


class CertIssuerSerializer(serializers.Serializer):
    ident_kwargs = IDentSerializer(
        source="get_ident_kwargs", required=False, allow_null=True)
    microsoft_ca_kwargs = MicrosoftCASerializer(
        source="get_microsoft_ca_kwargs", required=False, allow_null=True)
    okta_ca_kwargs = OktaCASerializer(
        source="get_okta_ca_kwargs", required=False, allow_null=True)
    static_challenge_kwargs = StaticChallengeSerializer(
        source="get_static_challenge_kwargs", required=False, allow_null=True)

    def validate(self, data):
        data = super().validate(data)
        # backend
        backend = CertIssuerBackend(data["backend"])
        # backend kwargs
        backend_slug = backend.value.lower()
        data["backend_kwargs"] = data.pop(f"get_{backend_slug}_kwargs", None)
        if not data["backend_kwargs"]:
            raise serializers.ValidationError(
                {f"{backend_slug}_kwargs": "This field is required."}
            )
        # other backend kwargs
        for other_backend in CertIssuerBackend:
            if other_backend == backend:
                continue
            other_backend_slug = other_backend.value.lower()
            if data.pop(f"get_{other_backend_slug}_kwargs", None):
                raise serializers.ValidationError(
                    {f"{other_backend_slug}_kwargs": "This field cannot be set for this backend."}
                )
        return data

    def create(self, validated_data):
        # we do not use the inherited create method because we want to avoid a double DB save
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        cert_issuer = self.Meta.model(pk=uuid.uuid4(), **validated_data)
        cert_issuer.set_backend_kwargs(backend_kwargs)
        cert_issuer.save()
        # version set to one, no need to refresh from DB
        return cert_issuer

    def update(self, instance, validated_data):
        # we do not use the inherited create method because we want to avoid a double DB save
        backend_kwargs = validated_data.pop("backend_kwargs", {})
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.set_backend_kwargs(backend_kwargs)
        instance.save()
        # version updated in the DB, we need to refresh to resolve the value
        instance.refresh_from_db()
        return instance

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if instance.provisioning_uid:
            for field in list(ret.keys()):
                if field == "backend" or "kwargs" in field:
                    ret.pop(field)
        else:
            # other backends kwargs
            for other_backend in CertIssuerBackend:
                if other_backend == ret["backend"]:
                    continue
                other_backend_slug = other_backend.value.lower()
                ret.pop(f"{other_backend_slug}_kwargs", None)
        return ret


class ACMEIssuerSerializer(CertIssuerSerializer, serializers.ModelSerializer):
    class Meta:
        model = ACMEIssuer
        fields = (
            "id",
            "provisioning_uid",
            "name",
            "description",
            "version",
            "created_at",
            "updated_at",
            # specific fields
            "directory_url",
            "key_size",
            "key_type",
            "usage_flags",
            "extended_key_usage",
            "hardware_bound",
            "attest",
            # backends
            "backend",
            "ident_kwargs",
            "microsoft_ca_kwargs",
            "okta_ca_kwargs",
            "static_challenge_kwargs",
        )

    def validate(self, data):
        data = super().validate(data)
        key_size = data.get("key_size")
        key_type = data.get("key_type")
        attest = data.get("attest")
        hardware_bound = data.get("hardware_bound")
        if key_type == "RSA":
            if hardware_bound:
                raise serializers.ValidationError(
                    {"key_type": "Hardware bound keys must be of type ECSECPrimeRandom"}
                )
            if key_size < 1024 or key_size > 4096 or key_size % 8:
                raise serializers.ValidationError(
                    {"key_size": "RSA Key size must be a multiple of 8 in the range of 1024 through 4096"}
                )
        else:
            if hardware_bound:
                if key_size not in (256, 384):
                    raise serializers.ValidationError(
                        {"key_size": "Hardware bound ECSECPrimeRandom keys must be one of the P-256 or P-384 curves"}
                    )
            else:
                if key_size not in (192, 256, 384, 521):
                    raise serializers.ValidationError(
                        {"key_size": "ECSECPrimeRandom keys must be one of the P-192, P-256, P-384, or P-521 curves"}
                    )
        if attest and not hardware_bound:
            raise serializers.ValidationError(
                {"hardware_bound": "When attest is true, hardware_bound also needs to be true"}
            )
        return data


class SCEPIssuerSerializer(CertIssuerSerializer, serializers.ModelSerializer):
    class Meta:
        model = SCEPIssuer
        fields = (
            "id",
            "provisioning_uid",
            "name",
            "description",
            "version",
            "created_at",
            "updated_at",
            # specific fields
            "url",
            "key_size",
            "key_usage",
            # backends
            "backend",
            "ident_kwargs",
            "microsoft_ca_kwargs",
            "okta_ca_kwargs",
            "static_challenge_kwargs",
        )


class SoftwareUpdateEnforcementSerializer(serializers.ModelSerializer):
    latest_fields = ("max_os_version", "delay_days", "local_time")
    one_time_fields = ("os_version", "build_version", "local_datetime")

    class Meta:
        model = SoftwareUpdateEnforcement
        fields = "__all__"

    def _validate_os_version(self, value):
        if value and make_comparable_os_version(value) == (0, 0, 0):
            raise serializers.ValidationError("Not a valid OS version")
        return value

    def validate_max_os_version(self, value):
        return self._validate_os_version(value)

    def validate_os_version(self, value):
        return self._validate_os_version(value)

    def validate(self, data):
        max_os_version = data.get("max_os_version")
        os_version = data.get("os_version")
        if max_os_version and os_version:
            raise serializers.ValidationError("os_version and max_os_version cannot be both set")
        if max_os_version:
            mode = "max_os_version"
            required_fields = (f for f in self.latest_fields if f not in ("delay_days", "local_time"))
            other_fields = self.one_time_fields
        elif os_version:
            mode = "os_version"
            required_fields = (f for f in self.one_time_fields if f != "build_version")
            other_fields = self.latest_fields
        else:
            raise serializers.ValidationError("os_version or max_os_version are required")
        errors = {}
        for field in required_fields:
            value = data.get(field)
            if value is None or value == "":
                errors[field] = f"This field is required if {mode} is used"
        for field in other_fields:
            if data.get(field):
                errors[field] = f"This field cannot be set if {mode} is used"
            else:
                data[field] = "" if field not in ("delay_days", "local_time", "local_datetime") else None
        if errors:
            raise serializers.ValidationError(errors)
        return data


class BlueprintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blueprint
        exclude = ["serialized_artifacts"]


class FilteredBlueprintItemTagSerializer(serializers.Serializer):
    tag = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all())
    shard = serializers.IntegerField(min_value=1, max_value=100)


def validate_filtered_blueprint_item_data(data):
    # platforms & min max versions
    platform_active = False
    if not data:
        return
    artifact = data.get("artifact")
    for platform in Platform.values:
        field = platform.lower()
        if data.get(field, False):
            platform_active = True
            if artifact and platform not in artifact.platforms:
                raise serializers.ValidationError({field: "Platform not available for this artifact"})
    if not platform_active:
        raise serializers.ValidationError("You need to activate at least one platform")
    # shards
    shard_modulo = data.get("shard_modulo")
    default_shard = data.get("default_shard")
    if isinstance(shard_modulo, int) and isinstance(default_shard, int) and default_shard > shard_modulo:
        raise serializers.ValidationError({"default_shard": "Must be less than or equal to the shard modulo"})
    # excluded tags
    excluded_tags = data.get("excluded_tags", [])
    # tag shards
    for tag_shard in data.get("tag_shards", []):
        tag = tag_shard.get("tag")
        if tag and tag in excluded_tags:
            raise serializers.ValidationError({"excluded_tags": f"Tag {tag} also present in the tag shards"})
        shard = tag_shard.get("shard")
        if isinstance(shard, int) and isinstance(shard_modulo, int) and shard > shard_modulo:
            raise serializers.ValidationError({"tag_shards": f"Shard for tag {tag} > shard modulo"})


class BlueprintArtifactSerializer(serializers.ModelSerializer):
    excluded_tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True,
                                                       default=list, required=False)
    tag_shards = FilteredBlueprintItemTagSerializer(many=True, default=list, required=False)

    class Meta:
        model = BlueprintArtifact
        fields = "__all__"

    def validate(self, data):
        validate_filtered_blueprint_item_data(data)
        return data

    def create(self, validated_data):
        tag_shards = validated_data.pop("tag_shards")
        with transaction.atomic(durable=True):
            instance = super().create(validated_data)
            for tag_shard in tag_shards:
                BlueprintArtifactTag.objects.create(blueprint_artifact=instance, **tag_shard)
        with transaction.atomic(durable=True):
            update_blueprint_serialized_artifacts(instance.blueprint)
        return instance

    def update(self, instance, validated_data):
        tag_shard_dict = {tag_shard["tag"]: tag_shard["shard"] for tag_shard in validated_data.pop("tag_shards")}
        with transaction.atomic(durable=True):
            instance = super().update(instance, validated_data)
            instance.item_tags.exclude(tag__in=tag_shard_dict.keys()).delete()
            for tag, shard in tag_shard_dict.items():
                BlueprintArtifactTag.objects.update_or_create(
                    blueprint_artifact=instance,
                    tag=tag,
                    defaults={"shard": shard}
                )
        with transaction.atomic(durable=True):
            update_blueprint_serialized_artifacts(instance.blueprint)
        return instance


class ArtifactVersionSerializer(serializers.Serializer):
    id = serializers.UUIDField(read_only=True, source="artifact_version.pk")
    artifact = serializers.PrimaryKeyRelatedField(queryset=Artifact.objects.all(),
                                                  source="artifact_version.artifact")
    ios = serializers.BooleanField(required=False, default=False,
                                   source="artifact_version.ios")
    ios_min_version = serializers.CharField(required=False, default="", allow_blank=True,
                                            source="artifact_version.ios_min_version")
    ios_max_version = serializers.CharField(required=False, default="", allow_blank=True,
                                            source="artifact_version.ios_max_version")
    ipados = serializers.BooleanField(required=False, default=False,
                                      source="artifact_version.ipados")
    ipados_min_version = serializers.CharField(required=False, default="", allow_blank=True,
                                               source="artifact_version.ipados_min_version")
    ipados_max_version = serializers.CharField(required=False, default="", allow_blank=True,
                                               source="artifact_version.ipados_max_version")
    macos = serializers.BooleanField(required=False, default=False,
                                     source="artifact_version.macos")
    macos_min_version = serializers.CharField(required=False, default="", allow_blank=True,
                                              source="artifact_version.macos_min_version")
    macos_max_version = serializers.CharField(required=False, default="", allow_blank=True,
                                              source="artifact_version.macos_max_version")
    tvos = serializers.BooleanField(required=False, default=False,
                                    source="artifact_version.tvos")
    tvos_min_version = serializers.CharField(required=False, default="", allow_blank=True,
                                             source="artifact_version.tvos_min_version")
    tvos_max_version = serializers.CharField(required=False, default="", allow_blank=True,
                                             source="artifact_version.tvos_max_version")
    shard_modulo = serializers.IntegerField(min_value=1, max_value=100, default=100,
                                            source="artifact_version.shard_modulo")
    default_shard = serializers.IntegerField(min_value=0, max_value=100, default=100,
                                             source="artifact_version.default_shard")
    excluded_tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True,
                                                       default=list, required=False,
                                                       source="artifact_version.excluded_tags")
    tag_shards = FilteredBlueprintItemTagSerializer(many=True,
                                                    default=list, required=False,
                                                    source="artifact_version.tag_shards")
    version = serializers.IntegerField(min_value=1, source="artifact_version.version")
    created_at = serializers.DateTimeField(read_only=True, source="artifact_version.created_at")
    updated_at = serializers.DateTimeField(read_only=True, source="artifact_version.updated_at")

    def validate(self, data):
        # filters
        artifact_version = data.get("artifact_version")
        validate_filtered_blueprint_item_data(artifact_version)
        # version conflict
        artifact = artifact_version.get("artifact")
        version = artifact_version.get("version")
        if artifact and isinstance(version, int):
            version_conflict_qs = artifact.artifactversion_set.filter(version=version)
            if self.instance is not None:
                version_conflict_qs = version_conflict_qs.exclude(pk=self.instance.artifact_version.pk)
            if version_conflict_qs.count():
                raise serializers.ValidationError(
                    {"version": "A version of this artifact with the same version number already exists"}
                )
        return data

    def create(self, validated_data):
        data = validated_data.pop("artifact_version")
        excluded_tags = data.pop("excluded_tags")
        tag_shards = data.pop("tag_shards")
        artifact_version = ArtifactVersion.objects.create(**data)
        artifact_version.excluded_tags.set(excluded_tags)
        for tag_shard in tag_shards:
            ArtifactVersionTag.objects.create(artifact_version=artifact_version, **tag_shard)
        return artifact_version

    def update(self, instance, validated_data):
        data = validated_data.pop("artifact_version")
        excluded_tags = data.pop("excluded_tags")
        tag_shard_dict = {tag_shard["tag"]: tag_shard["shard"] for tag_shard in data.pop("tag_shards")}
        artifact_version = instance.artifact_version
        for attr, value in data.items():
            setattr(artifact_version, attr, value)
        artifact_version.save()
        artifact_version.excluded_tags.set(excluded_tags)
        artifact_version.item_tags.exclude(tag__in=tag_shard_dict.keys()).delete()
        for tag, shard in tag_shard_dict.items():
            ArtifactVersionTag.objects.update_or_create(
                artifact_version=artifact_version,
                tag=tag,
                defaults={"shard": shard}
            )
        return artifact_version


class B64EncodedBinaryField(serializers.Field):
    def to_representation(self, value):
        return base64.b64encode(value).decode("ascii")

    def to_internal_value(self, data):
        return base64.b64decode(data)


class DataAssetSerializer(ArtifactVersionSerializer):
    type = serializers.ChoiceField(required=True, choices=DataAsset.Type.choices)
    file_uri = serializers.CharField(required=True, write_only=True)
    file_sha256 = serializers.RegexField(r"[0-9a-f]{64}", required=True)
    file_size = serializers.IntegerField(read_only=True)
    filename = serializers.CharField(read_only=True)

    def validate(self, data):
        data = super().validate(data)
        # type
        data_asset_type = DataAsset.Type(data["type"])
        if data_asset_type == DataAsset.Type.PLIST:
            supported_file_extensions = (".plist",)
        elif data_asset_type == DataAsset.Type.ZIP:
            supported_file_extensions = (".zip",)
        else:
            raise RuntimeError("Unknown data asset type")
        # download external resource
        try:
            filename, tmp_file = download_external_resource(
                data["file_uri"], data["file_sha256"],
                supported_file_extensions
            )
        except Exception as e:
            raise serializers.ValidationError({"file_uri": str(e)})
        # verify file type
        if data_asset_type == DataAsset.Type.PLIST:
            try:
                plistlib.load(tmp_file)
            except Exception:
                tmp_file.close()
                os.unlink(tmp_file.name)
                raise serializers.ValidationError({"file_uri": "Invalid PLIST file"})
        elif data_asset_type == DataAsset.Type.ZIP:
            if not zipfile.is_zipfile(tmp_file):
                tmp_file.close()
                os.unlink(tmp_file.name)
                raise serializers.ValidationError({"file_uri": "Invalid ZIP file"})
        # verify last version
        latest_data_asset = (
            DataAsset.objects.filter(artifact_version__artifact=data["artifact_version"]["artifact"])
                             .order_by("-artifact_version__version")
                             .first()
        )
        if latest_data_asset and latest_data_asset.file_sha256 == data["file_sha256"]:
            raise serializers.ValidationError({"file_uri": "This file is not different from the latest one"})
        # add data asset info
        tmp_file.seek(0)
        file = File(tmp_file)
        data["data_asset"] = {
            "type": data_asset_type,
            "file": file,
            "filename": filename,
            "file_sha256": data["file_sha256"],
            "file_size": file.size
        }
        return data

    def create(self, validated_data):
        try:
            with transaction.atomic(durable=True):
                artifact_version = super().create(validated_data)
                instance = DataAsset.objects.create(
                    artifact_version=artifact_version,
                    **validated_data["data_asset"]
                )
            with transaction.atomic(durable=True):
                for blueprint in artifact_version.artifact.blueprints():
                    update_blueprint_serialized_artifacts(blueprint)
        finally:
            os.unlink(validated_data["data_asset"]["file"].name)
        return instance

    def update(self, instance, validated_data):
        try:
            with transaction.atomic(durable=True):
                super().update(instance, validated_data)
                for attr, value in validated_data["data_asset"].items():
                    setattr(instance, attr, value)
                instance.save()
            with transaction.atomic(durable=True):
                for blueprint in instance.artifact_version.artifact.blueprints():
                    update_blueprint_serialized_artifacts(blueprint)
        finally:
            os.unlink(validated_data["data_asset"]["file"].name)
        return instance


class DeclarationSerializer(ArtifactVersionSerializer):
    source = serializers.JSONField(required=True, source="get_full_dict")

    def validate(self, data):
        data = super().validate(data)
        artifact = data["artifact_version"]["artifact"]
        declaration = self.instance if (self.instance and self.instance.pk) else None
        try:
            info = verify_declaration_source(
                artifact,
                data["get_full_dict"],
                declaration,
                ensure_server_token=False,
            )
        except ValueError as e:
            raise serializers.ValidationError({"source": str(e)})
        data["declaration"] = info
        return data

    def create(self, validated_data):
        refs = validated_data["declaration"].pop("refs")
        with transaction.atomic(durable=True):
            artifact_version = super().create(validated_data)
            instance = Declaration.objects.create(
                artifact_version=artifact_version,
                **validated_data["declaration"]
            )
            # update refs
            for key, ref_artifact in refs.items():
                DeclarationRef.objects.create(declaration=instance, key=key, artifact=ref_artifact)
        with transaction.atomic(durable=True):
            for blueprint in artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return instance

    def update(self, instance, validated_data):
        refs = validated_data["declaration"].pop("refs")
        with transaction.atomic(durable=True):
            super().update(instance, validated_data)
            for attr, value in validated_data["declaration"].items():
                setattr(instance, attr, value)
            instance.save()
            # update refs
            seen_keys = []
            for key, ref_artifact in refs.items():
                DeclarationRef.objects.update_or_create(
                    declaration=instance,
                    key=key,
                    defaults={"artifact": ref_artifact}
                )
                seen_keys.append(tuple(key))
            for decl_ref in DeclarationRef.objects.filter(declaration=instance):
                if tuple(decl_ref.key) not in seen_keys:
                    decl_ref.delete()
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return instance


class ProfileSerializer(ArtifactVersionSerializer):
    source = B64EncodedBinaryField()

    def validate(self, data):
        data = super().validate(data)
        source = data.pop("source", None)
        if source is None:
            return data
        try:
            source, info = get_configuration_profile_info(source)
        except ValueError as e:
            raise serializers.ValidationError({"source": str(e)})
        data["profile"] = info
        data["profile"]["source"] = source
        data["profile"].pop("channel")
        return data

    def create(self, validated_data):
        with transaction.atomic(durable=True):
            artifact_version = super().create(validated_data)
            instance = Profile.objects.create(
                artifact_version=artifact_version,
                **validated_data["profile"]
            )
        with transaction.atomic(durable=True):
            for blueprint in artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return instance

    def update(self, instance, validated_data):
        with transaction.atomic(durable=True):
            super().update(instance, validated_data)
            for attr, value in validated_data["profile"].items():
                setattr(instance, attr, value)
            instance.save()
        with transaction.atomic(durable=True):
            for blueprint in instance.artifact_version.artifact.blueprints():
                update_blueprint_serialized_artifacts(blueprint)
        return instance


class EnterpriseAppSerializer(ArtifactVersionSerializer):
    package_uri = serializers.CharField(required=True)
    package_sha256 = serializers.CharField(required=True)
    package_size = serializers.IntegerField(read_only=True)
    filename = serializers.CharField(read_only=True)
    product_id = serializers.CharField(read_only=True)
    product_version = serializers.CharField(read_only=True)
    configuration = serializers.CharField(required=False, source="get_configuration_plist",
                                          default=None, allow_null=True)
    bundles = serializers.JSONField(read_only=True)
    manifest = serializers.JSONField(read_only=True)
    ios_app = serializers.BooleanField(required=False, default=False)
    install_as_managed = serializers.BooleanField(required=False, default=False)
    remove_on_unenroll = serializers.BooleanField(required=False, default=False)

    def validate_configuration(self, value):
        try:
            return validate_configuration(value)
        except ValueError as e:
            raise serializers.ValidationError(str(e))

    def validate(self, data):
        data = super().validate(data)
        if data.get("remove_on_unenroll") and not data.get("install_as_managed"):
            raise serializers.ValidationError({
                "remove_on_unenroll": "Only available if installed as managed is also set"
            })
        package_uri = data.get("package_uri")
        if package_uri is None:
            return data
        package_sha256 = data.get("package_sha256")
        if package_sha256 is None:
            return data
        try:
            filename, tmp_file = download_external_resource(package_uri, package_sha256, (".pkg", ".ipa"))
            _, _, ea_data = read_package_info(tmp_file)
        except Exception as e:
            raise serializers.ValidationError({"package_uri": str(e)})
        # same product ID?
        artifact = data["artifact_version"]["artifact"]
        if (
            EnterpriseApp.objects.filter(artifact_version__artifact=artifact)
                                 .exclude(product_id=ea_data["product_id"]).exists()
        ):
            raise serializers.ValidationError(
                {"package_uri": "The product ID of the new app is not identical "
                                "to the product ID of the other versions"}
            )
        # non-field attributes
        ea_data["filename"] = filename
        ea_data["package"] = File(tmp_file)
        # field attributes
        for attr in ("package_uri", "package_sha256",
                     "ios_app", "configuration",
                     "install_as_managed", "remove_on_unenroll"):
            if attr == "configuration":
                data_attr = "get_configuration_plist"
            else:
                data_attr = attr
            ea_data[attr] = data.pop(data_attr)
        data["enterprise_app"] = ea_data
        return data

    def create(self, validated_data):
        try:
            with transaction.atomic(durable=True):
                artifact_version = super().create(validated_data)
                instance = EnterpriseApp.objects.create(
                    artifact_version=artifact_version,
                    **validated_data["enterprise_app"]
                )
            with transaction.atomic(durable=True):
                for blueprint in artifact_version.artifact.blueprints():
                    update_blueprint_serialized_artifacts(blueprint)
        finally:
            os.unlink(validated_data["enterprise_app"]["package"].name)
        return instance

    def update(self, instance, validated_data):
        try:
            with transaction.atomic(durable=True):
                super().update(instance, validated_data)
                for attr, value in validated_data["enterprise_app"].items():
                    setattr(instance, attr, value)
                instance.save()
            with transaction.atomic(durable=True):
                for blueprint in instance.artifact_version.artifact.blueprints():
                    update_blueprint_serialized_artifacts(blueprint)
        finally:
            os.unlink(validated_data["enterprise_app"]["package"].name)
        return instance


class LocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = (
            "id",
            "server_token_expiration_date",
            "organization_name",
            "name",
            "country_code",
            "library_uid",
            "platform",
            "website_url",
            "mdm_info_id",
            "created_at",
            "updated_at",
        )


class LocationAssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = LocationAsset
        fields = "__all__"
