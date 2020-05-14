import logging
import uuid
from django.utils import timezone
from elasticsearch import Elasticsearch, RequestError
from elasticsearch.client import IlmClient
from zentral.core.exceptions import ImproperlyConfigured
from zentral.contrib.inventory.models import Source
from zentral.contrib.inventory.utils import SourceFilter
from .base import BaseExporter

logger = logging.getLogger("zentral.contrib.inventory.exporters.es_aggregations")


ES_ALIAS = "zentral-inventory-export-aggregations"
ES_LIFECYCLE_POLICY_NAME = ES_ALIAS
ES_LIFECYCLE_POLICY = {
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "1GB",
            "max_age": "15d",
            "max_docs": 1000000,
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}
ES_TEMPLATE_NAME = ES_ALIAS
ES_INDEX_PATTERN = '{}-*'.format(ES_ALIAS)
ES_TEMPLATE = {
    'index_patterns': [ES_INDEX_PATTERN],
    'settings': {'number_of_shards': 1,
                 'number_of_replicas': 0,
                 'index.lifecycle.name': ES_LIFECYCLE_POLICY_NAME,
                 'index.lifecycle.rollover_alias': ES_ALIAS},
    'mappings': {
        'date_detection': False,
        'dynamic_templates': [{'strings_as_keyword': {'mapping': {'ignore_above': 1024,
                                                                  'type': 'keyword'},
                                                      'match_mapping_type': 'string'}}],
        'properties': {
            'source': {
                "properties": {
                    "id": {"type": "integer"},
                    "module": {"type": "keyword"},
                    "name": {"type": "keyword"},
                    "display_name": {"type": "keyword"},
                }
            },
            'filter': {
                "properties": {
                    "title": {"type": "keyword"},
                    "slug": {"type": "keyword"},
                }
            },
            'value': {"type": "keyword"},
            'count': {"type": "integer"},
            '@timestamp': {'type': 'date'},
        }
    }
}


class InventoryExporter(BaseExporter):
    name = "elasticsearch aggregations exporter"

    def __init__(self, config_g):
        super().__init__(config_g)
        error_msgs = []
        self.es_hosts = config_g["es_hosts"]
        if not self.es_hosts:
            error_msgs.append("Missing es_hosts")
        if not isinstance(self.es_hosts, list):
            error_msgs.append("es_hosts must be a list")
        if error_msgs:
            raise ImproperlyConfigured("{} in {}".format(", ".join(error_msgs), self.name))

    def iter_machine_snapshots(self):
        for serial_number, machine_snapshots in self.get_ms_query().fetch(paginate=False, for_filtering=True):
            for machine_snapshot in machine_snapshots:
                yield machine_snapshot

    def get_es_client(self):
        self._es = Elasticsearch(hosts=self.es_hosts)
        self._es_version = [int(i) for i in self._es.info()["version"]["number"].split(".")]
        if self._es_version < [7]:
            raise ValueError("Inventory exporter {} not compatible with ES < 7.0")
        # lifecycle
        _esilm = IlmClient(self._es)
        _esilm.put_lifecycle(ES_LIFECYCLE_POLICY_NAME, ES_LIFECYCLE_POLICY)
        # template
        self._es.indices.put_template(ES_TEMPLATE_NAME, ES_TEMPLATE)
        # create index
        for i in range(10):
            existing_indices = self._es.indices.get(ES_INDEX_PATTERN).keys()
            if not len(existing_indices):
                current_index_name = ES_INDEX_PATTERN.replace("*", "000001")
                try:
                    self._es.indices.create(current_index_name, {"aliases": {ES_ALIAS: {"is_write_index": True}}})
                except RequestError:
                    # probably race
                    pass
                else:
                    break
        return ES_ALIAS

    def run(self):
        timestamp = timezone.now().isoformat()
        index_name = self.get_es_client()
        for source in Source.objects.current_machine_snapshot_sources():
            ms_query = self.get_ms_query()
            source_d = {"id": source.pk,
                        "module": source.module,
                        "name": source.name,
                        "display_name": source.get_display_name()}
            ms_query.force_filter(SourceFilter, hidden_value=source.pk)
            for f, f_links, _, _ in ms_query.grouping_links():
                filter_d = {"title": f.title, "slug": f.get_query_kwarg()}
                for label, f_count, _, _, _ in f_links:
                    if label == "\u2400":
                        label = "NULL"
                    elif not isinstance(label, str):
                        label = str(label)
                    doc = {"source": source_d,
                           "filter": filter_d,
                           "value": label,
                           "count": f_count,
                           "@timestamp": timestamp}
                    doc_id = str(uuid.uuid4())
                    self._es.create(index_name, doc_id, doc)
