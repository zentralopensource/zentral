import hashlib
from django.urls import reverse_lazy
from rest_framework import serializers
from .base import register_probe_class, BaseProbeSerializer, OsqueryResultProbe, OsqueryQuery


class FilePath(object):
    def __init__(self, probe, file_path, file_access, hash_length=OsqueryResultProbe.hash_length):
        self.probe = probe
        self.file_path = file_path
        self.file_access = file_access
        self.hash_length = hash_length
        self.category = hashlib.sha1(file_path.encode("utf-8")).hexdigest()[:hash_length]

    def get_osquery_query(self):
        return OsqueryQuery(probe=self.probe,
                            query="select * from file_events where category='{}'".format(self.category),
                            interval=30,  # TODO: hard coded
                            platform=['darwin', 'freebsd', 'linux'],
                            hash_length=self.hash_length)


class FilePathSerializer(serializers.Serializer):
    file_path = serializers.CharField()
    file_access = serializers.BooleanField(default=False)


class OsqueryFIMProbeSerializer(BaseProbeSerializer):
    file_paths = serializers.ListField(
        child=FilePathSerializer()
    )


class OsqueryFIMProbe(OsqueryResultProbe):
    serializer_class = OsqueryFIMProbeSerializer
    model_display = "osquery fim"
    create_url = reverse_lazy("osquery:create_fim_probe")
    template_name = "osquery/fim_probe.html"
    can_edit_payload_filters = False

    def load_validated_data(self, data):
        super().load_validated_data(data)
        self.file_paths = [FilePath(probe=self, hash_length=self.hash_length, **file_path_data)
                           for file_path_data in data["file_paths"]]
        self.can_delete_file_paths = len(self.file_paths) > 1

    def iter_scheduled_queries(self):
        for file_path in self.file_paths:
            yield file_path.get_osquery_query()

    def get_extra_event_search_dict(self):
        return {'event_type': self.forced_event_type,
                'name__regexp': '{s}_[0-9a-f]{{{l}}}'.format(s=self.slug, l=self.hash_length)}


register_probe_class(OsqueryFIMProbe)
