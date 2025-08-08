from django.db.models import F
from django.urls import reverse
from django.utils.text import slugify
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .compliance_checks import sync_query_compliance_check
from .models import (Configuration, Enrollment, Pack, Platform, Query, AutomaticTableConstruction, FileCategory,
                     ConfigurationPack, PackQuery)


class AutomaticTableConstructionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AutomaticTableConstruction
        fields = '__all__'


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = '__all__'


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()
    script_download_url = serializers.SerializerMethodField()
    powershell_script_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        # TODO: distributor, maybe with a link ?
        fields = ("id", "configuration",
                  "osquery_release", "secret", "version",
                  "enrolled_machines_count",
                  "package_download_url", "powershell_script_download_url", "script_download_url",
                  "created_at", "updated_at")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_artifact_download_url(self, view_name, obj):
        path = reverse(f"osquery_api:{view_name}", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

    def get_package_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_package", obj)

    def get_powershell_script_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_powershell_script", obj)

    def get_script_download_url(self, obj):
        return self.get_artifact_download_url("enrollment_script", obj)

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


# FileCategory

class FileCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = FileCategory
        fields = '__all__'

    def validate(self, data):
        name = data.get("name")
        slug = slugify(name)
        fc_qs = FileCategory.objects.all()
        if self.instance:
            fc_qs = fc_qs.exclude(pk=self.instance.pk)
        if fc_qs.filter(slug=slug).exists():
            raise serializers.ValidationError({"name": f"file category with this slug {slug} already exists."})
        else:
            data["slug"] = slug
        return data


# Standard Osquery packs

class OsqueryPlatformField(serializers.ListField):
    def to_internal_value(self, data):
        platforms = []
        if data:
            platform_set = set(data.lower().split(","))
            if platform_set:
                unknown_platforms = platform_set - Platform.accepted_platforms()
                if unknown_platforms:
                    raise serializers.ValidationError(
                        'Unknown platforms: {}'.format(", ".join(sorted(unknown_platforms)))
                    )
            platforms = sorted(platform_set)
        return platforms


class OsqueryQuerySerializer(serializers.Serializer):
    query = serializers.CharField(allow_blank=False)
    interval = serializers.IntegerField(min_value=1, max_value=604800)
    removed = serializers.BooleanField(required=False)
    snapshot = serializers.BooleanField(required=False)
    platform = OsqueryPlatformField(required=False)
    version = serializers.RegexField(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$", required=False)
    shard = serializers.IntegerField(min_value=1, max_value=100, required=False)
    denylist = serializers.BooleanField(default=True, required=False)
    description = serializers.CharField(allow_blank=True, required=False)
    value = serializers.CharField(allow_blank=False, required=False)
    compliance_check = serializers.BooleanField(default=False, required=False)

    def validate(self, data):
        snapshot = data.get("snapshot", False)
        if snapshot and data.get("removed"):
            raise serializers.ValidationError('{"action": "removed"} results are not available in "snapshot" mode')
        if data.get("compliance_check"):
            if not snapshot:
                raise serializers.ValidationError('{"compliance_check": true} only available in "snapshot" mode')
            sql = data.get("query")
            if sql is not None and 'ztl_status' not in sql:
                raise serializers.ValidationError('{"compliance_check": true} only if query contains "ztl_status"')
        return data


class OsqueryPackSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=256, required=False)
    description = serializers.CharField(required=False)
    discovery = serializers.ListField(child=serializers.CharField(allow_blank=False), allow_empty=True, required=False)
    platform = OsqueryPlatformField(required=False)
    version = serializers.RegexField(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$", required=False)
    shard = serializers.IntegerField(min_value=1, max_value=100, required=False)
    queries = serializers.DictField(child=OsqueryQuerySerializer(), allow_empty=False)
    event_routing_key = serializers.RegexField(r'^[-a-zA-Z0-9_]+\Z', required=False)

    def validate_queries(self, value):
        if isinstance(value, dict) and "" in value:
            raise serializers.ValidationError("Query name cannot be empty")
        return value

    def get_pack_defaults(self, slug):
        return {
            "name": self.data.get("name", slug),
            "description": self.data.get("description", ""),
            "discovery_queries": self.data.get("discovery", []),
            "shard": self.data.get("shard", None),
            "event_routing_key": self.data.get("event_routing_key", ""),
        }

    def iter_query_defaults(self, pack_slug):
        pack_platforms = self.data.get("platform", [])
        pack_minimum_osquery_version = self.data.get("version", None)
        for query_slug, query_data in self.data["queries"].items():
            pack_query_defaults = {
                "slug": query_slug,
                "interval": query_data["interval"],
                "log_removed_actions": not query_data.get("snapshot", False) and query_data.get("removed", True),
                "snapshot_mode": query_data.get("snapshot", False),
                "shard": query_data.get("shard"),
                "can_be_denylisted": query_data.get("can_be_denylisted", True),
            }
            query_defaults = {
                "name": f"{pack_slug}{Pack.DELIMITER}{query_slug}",
                "sql": query_data["query"],
                "platforms": query_data.get("platform", pack_platforms),
                "minimum_osquery_version": query_data.get("version", pack_minimum_osquery_version),
                "description": query_data.get("description", ""),
                "value": query_data.get("value", ""),
                "compliance_check": query_data.get("compliance_check") or False
            }
            yield query_slug, pack_query_defaults, query_defaults


class QuerySchedulingSerializer(serializers.ModelSerializer):
    pack = serializers.PrimaryKeyRelatedField(queryset=Pack.objects.all())

    class Meta:
        model = PackQuery
        fields = ("pack", "interval", "log_removed_actions", "snapshot_mode", "shard", "can_be_denylisted")

    def validate(self, data):
        if data.get("snapshot_mode") and data.get("log_removed_actions"):
            raise serializers.ValidationError({
                "snapshot_mode": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"],
                "log_removed_actions": ["'log_removed_actions' and 'snapshot_mode' are mutually exclusive"]
            })
        return data


class QuerySerializer(serializers.ModelSerializer):
    compliance_check_enabled = serializers.BooleanField(default=False)
    scheduling = QuerySchedulingSerializer(source="packquery", required=False, allow_null=True)

    class Meta:
        model = Query
        exclude = ("compliance_check",)

    def validate(self, data):
        compliance_check_enabled = data.get("compliance_check_enabled")
        tag = data.get("tag")
        # compliance check & tag mutually exclusive
        if compliance_check_enabled and tag:
            err = "A query can either be a compliance check or a tag update, not both"
            raise serializers.ValidationError({
                'compliance_check_enabled': err,
                'tag': err,
            })
        # check compliance check query syntax
        if compliance_check_enabled:
            sql = data.get("sql")
            if sql is not None and 'ztl_status' not in sql:
                raise serializers.ValidationError({'compliance_check_enabled': 'ztl_status not in sql'})
        # check query scheduling during update
        if compliance_check_enabled or tag:
            try:
                pack_query = self.instance.packquery
            except AttributeError:
                pass
            else:
                if not pack_query.snapshot_mode:
                    err_key = "tag" if tag else "compliance_check_enabled"
                    raise serializers.ValidationError(
                        {err_key: f'query scheduled in diff mode in {pack_query.pack} pack'})
        # check query scheduling during creation
        pack_data = data.get("packquery")
        if not pack_data:
            return data
        if not pack_data.get("snapshot_mode"):
            if compliance_check_enabled:
                raise serializers.ValidationError({
                    "scheduling": {
                        "snapshot_mode": ["A compliance check query can only be scheduled in 'snapshot' mode."]
                    }
                })
            if tag:
                raise serializers.ValidationError({
                    "scheduling": {
                        "snapshot_mode": ["A tag update query can only be scheduled in 'snapshot' mode."]
                    }
                })
        return data

    def create(self, validated_data):
        compliance_check_enabled = validated_data.pop("compliance_check_enabled")
        pack_query_data = validated_data.pop("packquery", {})
        query = Query.objects.create(**validated_data)
        if pack_query_data:
            slug = slugify(query.name)
            if PackQuery.objects.filter(slug=slug).exists():
                slug = f"{slug}-{query.pk}"
            pack_query_data["slug"] = slug
            pack_query_data["query"] = query
            PackQuery.objects.create(**pack_query_data)
        sync_query_compliance_check(query, compliance_check_enabled)
        return query

    def update(self, instance, validated_data):
        compliance_check_enabled = validated_data.pop("compliance_check_enabled")
        pack_query_data = validated_data.pop("packquery", {})
        sql = validated_data.get("sql")
        if sql and sql != instance.sql:
            validated_data["version"] = F("version") + 1
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        sync_query_compliance_check(instance, compliance_check_enabled)
        try:
            instance_pack_query = instance.packquery
        except PackQuery.DoesNotExist:
            instance_pack_query = None
        if pack_query_data:
            slug = slugify(instance.name)
            slug_qs = PackQuery.objects.filter(slug=slug)
            if instance_pack_query:
                slug_qs = slug_qs.exclude(pk=instance_pack_query.pk)
            if slug_qs.exists():
                slug = f"{slug}-{instance.pk}"
            pack_query_data["slug"] = slug
        if instance_pack_query and not pack_query_data:
            instance_pack_query.delete()
        elif pack_query_data:
            if instance_pack_query:
                for attr, value in pack_query_data.items():
                    setattr(instance_pack_query, attr, value)
                instance_pack_query.save()
            else:
                PackQuery.objects.create(query=instance, **pack_query_data)
        instance.refresh_from_db()
        return instance


class ConfigurationPackSerializer(serializers.ModelSerializer):
    configuration = serializers.PrimaryKeyRelatedField(queryset=Configuration.objects.all())

    class Meta:
        model = ConfigurationPack
        fields = "__all__"

    def validate(self, data):
        data = super().validate(data)
        tags = data.get("tags")
        excluded_tags = data.get("excluded_tags")
        if tags and excluded_tags:
            common_tags = set(tags).intersection(excluded_tags)
            if common_tags:
                tag_names = ", ".join(sorted(f"'{t.name}'" for t in common_tags))
                raise serializers.ValidationError(f"{tag_names} cannot be both included and excluded")
        return data


class PackSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pack
        fields = "__all__"

    def validate(self, data):
        name = data.get("name")
        slug = slugify(name)
        pack_qs = Pack.objects.all()
        if self.instance:
            pack_qs = pack_qs.exclude(id=self.instance.pk)
        if pack_qs.filter(slug=slug).exists():
            raise serializers.ValidationError({"name": f"Pack with this slug {slug} already exists"})
        else:
            data["slug"] = slug
        return data
