from django.urls import reverse
from rest_framework import serializers
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.serializers import EnrollmentSecretSerializer
from .models import Configuration, Enrollment, Pack, Platform


class ConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Configuration
        fields = ("id", "name", "description",
                  "inventory", "inventory_apps", "inventory_interval",
                  "options",
                  "created_at", "updated_at")


class EnrollmentSerializer(serializers.ModelSerializer):
    secret = EnrollmentSecretSerializer(many=False)
    enrolled_machines_count = serializers.SerializerMethodField()
    package_download_url = serializers.SerializerMethodField()

    class Meta:
        model = Enrollment
        # TODO: distributor, maybe with a link ?
        fields = ("id", "configuration",
                  "osquery_release", "secret", "version",
                  "enrolled_machines_count", "package_download_url")

    def get_enrolled_machines_count(self, obj):
        return obj.enrolledmachine_set.count()

    def get_package_download_url(self, obj):
        path = reverse("osquery_api:enrollment_package", args=(obj.pk,))
        return f'https://{settings["api"]["fqdn"]}{path}'

    def create(self, validated_data):
        secret_data = validated_data.pop('secret')
        secret = EnrollmentSecret.objects.create(**secret_data)
        enrollment = Enrollment.objects.create(secret=secret, **validated_data)
        return enrollment

    def update(self, instance, validated_data):
        secret_serializer = self.fields["secret"]
        secret_data = validated_data.pop('secret')
        secret_serializer.update(instance.secret, secret_data)
        return super().update(instance, validated_data)


# Standard Osquery packs


class OsqueryPlatformField(serializers.ListField):
    def to_internal_value(self, data):
        if data:
            platforms = set(data.lower().split(","))
            if platforms:
                unknown_platforms = platforms - Platform.accepted_platforms()
                if unknown_platforms:
                    raise serializers.ValidationError(
                        'Unknown platforms: {}'.format(", ".join(sorted(unknown_platforms)))
                    )
            return sorted(platforms)
        return []


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

    def get_pack_defaults(self, slug):
        return {
            "name": self.data.get("name", slug),
            "description": self.data.get("description", ""),
            "discovery_queries": self.data.get("discovery", []),
            "shard": self.data.get("shard", None)
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
