import logging
import random
import time
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from zentral.core.events import event_from_event_d
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')

try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')

BASE_VISU_URL = ("{kibana_base_url}#/discover?_g=()&"
                 "_a=(columns:!(_source),index:{index},interval:auto,"
                 "query:(query_string:(analyze_wildcard:!t,query:'{query}')),"
                 "sort:!(zzzentral.created_at,desc))")

INDEX_CONF = """
{
  "mappings" : {
    "_default_" : {
      "properties": {
        "zzzentral": {
          "properties": {
            "request": {
              "properties": {
                "ip": {
                  "type": "ip",
                  "index": "not_analyzed"
                }
              }
            }
          }
        }
      },
      "dynamic_templates" : [
        {
          "zentral_ip_address" : {
            "match" : "*ip_address",
            "mapping" : {
              "type" : "ip",
              "index" : "not_analyzed"
            }
          }
        },
        {
          "zentral_string_default" : {
            "match" : "*",
            "match_mapping_type" : "string",
            "mapping" : {
              "type" : "string",
              "index" : "not_analyzed"
            }
          }
        }
      ]
    }
  }
}
"""


class EventStore(BaseEventStore):
    MAX_CONNECTION_ATTEMPTS = 10

    def __init__(self, config_d, test=False):
        super(EventStore, self).__init__(config_d)
        self._es = Elasticsearch(config_d['servers'])
        self.index = config_d['index']
        self.kibana_base_url = config_d.get('kibana_base_url', None)
        self.test = test

    def wait_and_configure(self):
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            try:
                if not self._es.indices.exists(self.index):
                    self._es.indices.create(self.index, body=INDEX_CONF)
            except ConnectionError as e:
                s = 1000 / random.randint(300, 1000)
                logger.warning('Could not connect to server %d/%d. Sleep %ss',
                               i + 1, self.MAX_CONNECTION_ATTEMPTS, s)
                time.sleep(s)
                continue
            except RequestError as e:
                if (e.info['status'] == 400 and
                    # Race
                    "IndexAlreadyExists".upper() in e.info['error']):
                    logger.info('Index %s exists', self.index)
                else:
                    raise
            logger.info('Index %s created', self.index)
            break
        else:
            raise Exception('Could not connect to server')

    def _serialize_event(self, event):
        event_d = event.serialize()
        event_d['zzzentral'] = event_d.pop('_zentral')
        return event.event_type, event_d

    def _deserialize_event(self, event_d):
        event_d['_zentral'] = event_d.pop('zzzentral')
        return event_from_event_d(event_d)

    def store(self, event_d):
        doc_type, body = self._serialize_event(event_d)
        try:
            self._es.index(index=self.index, doc_type=doc_type, body=body)
            if self.test:
                self._es.indices.refresh(self.index)
        except:
            logger.exception('Could not add event to elasticsearch index')

    def count(self, machine_serial_number, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        q = "zzzentral.machine_serial_number:{}".format(machine_serial_number)
        if event_type:
            q = "{} AND _type:{}".format(q, event_type)
        r = self._es.count(index=self.index, q=q)
        return r['count']

    def fetch(self, machine_serial_number, offset=0, limit=0, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        q = "zzzentral.machine_serial_number:{}".format(machine_serial_number)
        if event_type:
            q = "{} AND _type:{}".format(q, event_type)
        kwargs = {'index': self.index,
                  'q': q,
                  'sort': 'zzzentral.created_at:desc'}
        if limit:
            kwargs['size'] = limit
        if offset:
            kwargs['from_'] = offset
        r = self._es.search(**kwargs)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_source'])

    def event_types_with_usage(self, machine_serial_number):
        body = {
            'query': {
                'query_string': {
                    'query': 'zzzentral.machine_serial_number:{}'.format(machine_serial_number)
                }
            },
            'aggs': {'doc_types': {"terms": {'field': '_type'}}}}
        r = self._es.search(index=self.index, body=body, search_type="count")
        types_d = {}
        for bucket in r['aggregations']['doc_types']['buckets']:
            types_d[bucket['key']] = bucket['doc_count']
        return types_d

    def close(self):
        for connection in self._es.transport.connection_pool.connections:
            if hasattr(connection, 'pool'):
                connection.pool.close()

    def get_visu_url(self, search_dict):
        # TODO: doc, better args, ...
        search_atoms = []
        for key, val in search_dict.items():
            wildcard = ""
            if key.endswith('__startswith'):
                key = key.replace('__startswith', '')
                wildcard = "*"
            atom = " OR ".join("%s:%s%s" % (key, elm, wildcard) for elm in val)
            search_atoms.append("(%s)" % atom)
        query = " OR ".join(search_atoms)
        if self.kibana_base_url:
            return BASE_VISU_URL.format(kibana_base_url=self.kibana_base_url,
                                        index=self.index,
                                        query=query)
