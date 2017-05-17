import logging
from django.urls import reverse, reverse_lazy
from rest_framework import serializers
from .base import register_probe_class, BaseProbe, BaseProbeSerializer

logger = logging.getLogger("zentral.contrib.osquery.probes.osquery_file_carve")


class OsqueryFileCarveProbeSerializer(BaseProbeSerializer):
    path = serializers.CharField()


class OsqueryFileCarveProbe(BaseProbe):
    serializer_class = OsqueryFileCarveProbeSerializer
    model_display = "osquery file carve"
    create_url = reverse_lazy("osquery:create_file_carve_probe")
    template_name = "osquery/file_carve_probe.html"
    forced_event_type = 'osquery_file_carve'

    def load_validated_data(self, data):
        super().load_validated_data(data)
        self.path = data["path"]
        self.distributed_query_name = "fc_{}".format(self.pk)

    @property
    def distributed_query(self):
        # TODO: better escaping
        escaped_path = self.path.replace("'", "''").replace('"', '""')
        return "SELECT * FROM carves WHERE path LIKE '{}' AND carve=1;".format(escaped_path)

    def test_event(self, event):
        if not super().test_event(event):
            return False
        # match probe pk
        try:
            return event.payload["probe"]["id"] == self.pk
        except KeyError:
            logger.warning("OsqueryFileCarveEvent w/o probe.id")
            return False

    def get_extra_links(self):
        return [("Sessions", "download", reverse("osquery:file_carve_probe_sessions", args=(self.pk,)))]

    def get_extra_event_search_dict(self):
        # match probe pk
        return {'event_type': self.forced_event_type,
                'probe.id': self.pk}


register_probe_class(OsqueryFileCarveProbe)
