import logging
from elasticsearch import Elasticsearch
from zentral.core.events import event_from_event_d
from zentral.core.stores.backends.base import BaseEventStore

logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')

BASE_VISU_URL = ("{kibana_base_url}#/discover?_g=()&"
                 "_a=(columns:!(_source),index:{index},interval:auto,"
                 "query:(query_string:(analyze_wildcard:!t,query:'{query}')),"
                 "sort:!(zzzentral.created_at,desc))")


class EventStore(BaseEventStore):
    def __init__(self, config_d, test=False):
        super(EventStore, self).__init__(config_d)
        self._es = Elasticsearch(config_d['servers'])
        self.index = config_d['index']
        self.kibana_base_url = config_d.get('kibana_base_url', None)
        self.test = test

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

    def count(self, machine_serial_number):
        # TODO: count could work from first fetch with elasticsearch.
        r = self._es.count(index=self.index, q='zzzentral.machine_serial_number:{}'.format(machine_serial_number))
        return r['count']

    def fetch(self, machine_serial_number, offset=0, limit=0):
        # TODO: count could work from first fetch with elasticsearch.
        kwargs = {'index': self.index,
                  'q': 'zzzentral.machine_serial_number:{}'.format(machine_serial_number),
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
