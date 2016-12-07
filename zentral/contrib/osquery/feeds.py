import copy
import os.path
from urllib.parse import urlparse
from rest_framework import serializers
from .probes.base import OsqueryQuerySerializer


PLATFORM_CHOICES_DICT = dict(OsqueryQuerySerializer.PLATFORM_CHOICES)


def validate_platform(value):
    if value:
        try:
            return [k for k in value.split(",") if PLATFORM_CHOICES_DICT[k]]
        except KeyError:
            raise serializers.ValidationError("Unknown platform value")


class PackQuerySerializer(serializers.Serializer):
    query = serializers.CharField()
    interval = serializers.IntegerField(min_value=10, max_value=2678400, default=3600)
    description = serializers.CharField(required=False)
    value = serializers.CharField(required=False)
    removed = serializers.BooleanField(required=False)
    platform = serializers.CharField(required=False)
    shard = serializers.IntegerField(min_value=1, max_value=100, required=False)
    version = serializers.RegexField('^[0-9]+\.[0-9]+\.[0-9]+\Z', required=False)

    def validate_platform(self, value):
        return validate_platform(value)


class PackSerializer(serializers.Serializer):
    platform = serializers.CharField(required=False)
    version = serializers.RegexField('^[0-9]+\.[0-9]+\.[0-9]+\Z', required=False)
    shard = serializers.IntegerField(min_value=1, max_value=100, required=False)
    discovery = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )
    queries = serializers.DictField(
        child=PackQuerySerializer()
    )

    def validate_platform(self, value):
        return validate_platform(value)

    def get_name(self, url):
        path = urlparse(url).path
        if not path:
            return url
        else:
            name = os.path.splitext(os.path.basename(path))[0]
            if name:
                return name
            else:
                return path

    def iter_feed_probes(self):
        osquery_probe_tmpl = {"model": "OsqueryProbe",
                              "body": {"queries": []}}
        discovery = self.validated_data.get("discovery")
        if discovery:
            osquery_probe_tmpl["body"]["discovery"] = discovery
        query_tmpl = {}
        for attr in ("platform", "shard", "version"):
            val = self.validated_data.get(attr)
            if val:
                query_tmpl[attr] = val
        for pack_query_name, pack_query_data in self.validated_data["queries"].items():
            osquery_probe_data = copy.deepcopy(osquery_probe_tmpl)
            osquery_probe_data["name"] = pack_query_name
            description = pack_query_data.get("description")
            if description:
                osquery_probe_data["description"] = description
            else:
                osquery_probe_data["description"] = ""
            query = copy.deepcopy(query_tmpl)
            query.update(pack_query_data)
            osquery_probe_data["body"]["queries"].append(query)
            yield pack_query_name, osquery_probe_data
