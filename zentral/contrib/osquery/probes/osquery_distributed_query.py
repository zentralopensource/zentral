import logging
from django.urls import reverse_lazy
from rest_framework import serializers
from .base import BaseProbe, BaseProbeSerializer

logger = logging.getLogger("zentral.contrib.osquery.probes.osquery_distributed_query")


class OsqueryDistributedQueryProbeSerializer(BaseProbeSerializer):
    distributed_query = serializers.CharField()


class OsqueryDistributedQueryProbe(BaseProbe):
    serializer_class = OsqueryDistributedQueryProbeSerializer
    model_display = "osquery distributed query"
    create_url = reverse_lazy("osquery:create_distributed_query_probe")
    template_name = "osquery/distributed_query_probe.html"
    forced_event_type = 'osquery_distributed_query_result'

    def load_validated_data(self, data):
        super().load_validated_data(data)
        self.distributed_query = data["distributed_query"]
        self.distributed_query_name = "dq_{}".format(self.pk)

    def test_event(self, event):
        if not super().test_event(event):
            return False
        # match probe pk
        try:
            return event.payload["probe"]["id"] == self.pk
        except KeyError:
            logger.warning("OsqueryDistributedQueryResultEvent w/o probe.id")
            return False
