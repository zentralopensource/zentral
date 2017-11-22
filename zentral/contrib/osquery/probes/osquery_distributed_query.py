import logging
from django.urls import reverse, reverse_lazy
from rest_framework import serializers
from zentral.utils.sql import format_sql
from .base import register_probe_class, BaseProbe, BaseProbeSerializer

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

    def get_extra_links(self):
        return [("Results table", "th", reverse("osquery:distributed_query_results_table", args=(self.pk,)))]

    def get_extra_event_search_dict(self):
        # match probe pk
        return {'event_type': self.forced_event_type,
                'probe.id': self.pk}

    def get_distributed_query_html(self):
        return format_sql(self.distributed_query)


register_probe_class(OsqueryDistributedQueryProbe)
