import logging
from django.utils import timezone
from elasticsearch import Elasticsearch, NotFoundError, RequestError
from zentral.core.exceptions import ImproperlyConfigured
from .base import BaseExporter

logger = logging.getLogger("zentral.contrib.inventory.exporters.es_machine_snapshots")


MAX_EXPORTS_COUNT = 3
ES_ALIAS = "zentral-inventory-export-machine-snapshots"
ES_TEMPLATE_NAME = ES_ALIAS
ES_INDEX_PATTERN = '{}-*'.format(ES_ALIAS)
ES_TEMPLATE = {
    'index_patterns': [ES_INDEX_PATTERN],
    'settings': {'number_of_shards': 1,
                 'number_of_replicas': 0},
    'mappings': {'date_detection': False,
                 'dynamic_templates': [{'strings_as_keyword': {'mapping': {'ignore_above': 1024,
                                                                           'type': 'keyword'},
                                                               'match_mapping_type': 'string'}}],
                 'properties': {'@timestamp': {'type': 'date'},
                                'tags': {'ignore_above': 1024,
                                         'type': 'keyword'}}}
}


class InventoryExporter(BaseExporter):
    name = "elasticsearch machine snapshots exporter"

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
        # template
        template_body = ES_TEMPLATE
        if self._es_version < [7]:
            template_body["mappings"] = {"_doc": template_body.pop("mappings")}
        self._es.indices.put_template(ES_TEMPLATE_NAME, template_body)
        # create index
        for i in range(10):
            existing_indices = self._es.indices.get(ES_INDEX_PATTERN).keys()
            if not len(existing_indices):
                next_id = 0
            else:
                next_id = max(int(index.rsplit("-", 1)[-1]) for index in existing_indices) + 1
            index_name = ES_INDEX_PATTERN.replace("*", "{:08d}".format(next_id))
            try:
                self._es.indices.create(index_name)
            except RequestError:
                # probably race
                pass
            else:
                # move alias
                update_aliases_body = {
                    "actions": [
                        {"add": {"index": index_name, "alias": ES_ALIAS}}
                    ]
                }
                try:
                    old_indices = self._es.indices.get_alias(ES_ALIAS)
                except NotFoundError:
                    old_indices = []
                for old_index in old_indices:
                    if old_index != index_name:
                        update_aliases_body["actions"].append(
                            {"remove": {"index": old_index, "alias": ES_ALIAS}}
                        )
                self._es.indices.update_aliases(update_aliases_body)
                return index_name

    def index_snapshot(self, index_name, machine_snapshot):
        doc_id = "{}.{}".format(machine_snapshot["serial_number"], machine_snapshot["source"]["id"])
        self._es.create(index_name, doc_id, machine_snapshot)

    def prune_exports(self):
        existing_indices = sorted(self._es.indices.get(ES_INDEX_PATTERN).keys(), reverse=True)
        for index_name in existing_indices[MAX_EXPORTS_COUNT:]:
            self._es.indices.delete(index_name)
            logger.info("Removed '%s' index", index_name)

    def run(self):
        timestamp = timezone.now().isoformat()
        index_name = self.get_es_client()
        logger.info("Created '%s' index", index_name)
        i = 0
        for machine_snapshot in self.iter_machine_snapshots():
            machine_snapshot["@timestamp"] = timestamp
            self.index_snapshot(index_name, machine_snapshot)
            i += 1
        logger.info("Added %s machine snapshot(s)", i)
        self.prune_exports()
