import base64
import os
from django.core.files import File
from django.db import transaction
from rest_framework import serializers
from zentral.contrib.inventory.models import Tag
from .app_manifest import download_package, read_package_info, validate_configuration
from .artifacts import update_blueprint_serialized_artifacts
from .models import (Artifact, ArtifactVersion, ArtifactVersionTag,
                     Blueprint, BlueprintArtifact, BlueprintArtifactTag,
                     EnterpriseApp, FileVaultConfig,
                     Platform, Profile,
                     RecoveryPasswordConfig)
from .payloads import get_configuration_profile_info


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
            filename, tmp_file = download_package(package_uri, package_sha256)
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
