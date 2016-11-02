import logging
import random
import time
import urllib.parse
from dateutil import parser
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError
from zentral.core.events import event_from_event_d
from zentral.core.stores.backends.base import BaseEventStore
from zentral.utils.rison import dumps as rison_dumps

logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')

try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


class EventStore(BaseEventStore):
    MAX_CONNECTION_ATTEMPTS = 20
    INDEX_CONF = {
        'mappings': {
            '_default_': {
                'dynamic_templates': [
                    {'zentral_ip_address': {
                        'mapping': {'type': 'ip'},
                        'match': '*ip_address'
                    }},
                    {'zentral_string_default': {
                        'mapping': {'index': 'not_analyzed', 'type': 'string'},
                        'match': '*',
                        'match_mapping_type': 'string'
                    }}
                ],
                'properties': {
                    'created_at': {
                        'type': 'date'
                    },
                    'request': {
                        'properties': {
                            'ip': {'type': 'ip'}
                        }
                    }
                }
            },
            'osquery_distributed_query_result': {
                'properties': {
                    'osquery_distributed_query_result': {
                        'properties': {
                            'result': {'enabled': False}
                        }
                    }
                }
            }
        }
    }
    INTERVAL_UNIT = {
        "hour": "h",
        "day": "d",
        "week": "w",
        "month": "M",
    }

    def __init__(self, config_d, test=False):
        super(EventStore, self).__init__(config_d)
        self._es = Elasticsearch(config_d['servers'])
        self.index = config_d['index']
        self.kibana_base_url = config_d.get('kibana_base_url', None)
        self.test = test

    def wait_and_configure(self):
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            # get or create index
            try:
                if not self._es.indices.exists(self.index):
                    self._es.indices.create(self.index, body=self.INDEX_CONF)
            except ConnectionError as e:
                s = 1000 / random.randint(200, 1000)
                logger.warning('Could not connect to server %d/%d. Sleep %ss',
                               i + 1, self.MAX_CONNECTION_ATTEMPTS, s)
                time.sleep(s)
                continue
            except RequestError as e:
                if e.info['status'] == 400 and \
                   "IndexAlreadyExists".upper() in e.info['error']:  # Race
                    logger.info('Index %s exists', self.index)
                else:
                    raise
            logger.info('Index %s created', self.index)
            break
        else:
            raise Exception('Could not connect to server')

    def _serialize_event(self, event):
        event_d = event.serialize()
        es_event_d = event_d.pop('_zentral')
        es_event_d.pop('type')  # document type in ES
        es_event_d[event.event_type] = event_d
        return event.event_type, es_event_d

    def _deserialize_event(self, event_type, es_event_d):
        event_d = es_event_d.pop(event_type)
        event_d['_zentral'] = es_event_d
        event_d['_zentral']['type'] = event_type
        return event_from_event_d(event_d)

    def store(self, event):
        doc_type, body = self._serialize_event(event)
        try:
            self._es.index(index=self.index, doc_type=doc_type, body=body)
            if self.test:
                self._es.indices.refresh(self.index)
        except:
            logger.exception('Could not add event to elasticsearch index')

    # machine events

    def _get_machine_events_body(search, machine_serial_number, event_type):
        body = {
            'query': {
                'bool': {
                    'filter': [
                        {'term': {'machine_serial_number': machine_serial_number}}
                    ]
                }
            }
        }
        if event_type:
            body['query']['bool']['filter'].append({'type': {'value': event_type}})
        return body

    def machine_events_count(self, machine_serial_number, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(machine_serial_number, event_type)
        body['size'] = 0
        r = self._es.search(index=self.index, body=body)
        return r['hits']['total']

    def machine_events_fetch(self, machine_serial_number, offset=0, limit=0, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(machine_serial_number, event_type)
        if offset:
            body['from'] = offset
        if limit:
            body['size'] = limit
        body['sort'] = [{'created_at': 'desc'}]
        r = self._es.search(index=self.index, body=body)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_type'], hit['_source'])

    def machine_events_types_with_usage(self, machine_serial_number):
        body = {
            'query': {
                'bool': {
                    'filter': [
                        {'term': {'machine_serial_number': machine_serial_number}}
                    ]
                }
            },
            'size': 0,
            'aggs': {
                'doc_types': {
                    'terms': {'field': '_type'}
                }
            }
        }
        r = self._es.search(index=self.index, body=body)
        types_d = {}
        for bucket in r['aggregations']['doc_types']['buckets']:
            types_d[bucket['key']] = bucket['doc_count']
        return types_d

    # probe events

    def _get_probe_events_body(self, probe, **search_dict):
        # TODO: doc, better args, ...
        query_filter = []

        # inventory and metadata filters
        for section, attributes in (("inventory", (("terms",
                                                    "machine.meta_business_units.id",
                                                    "meta_business_unit_ids"),
                                                   ("terms", "machine.tags.id", "tag_ids"),
                                                   ("terms", "machine.platform", "platforms"),
                                                   ("terms", "machine.type", "types"))),
                                    ("metadata", (("type", "value", "event_types"),
                                                  ("terms", "tags", "event_tags")))):
            section_should = []
            for section_filter in getattr(probe, "{}_filters".format(section)):
                section_filter_must = []
                for query_type, query_attribute, filter_attribute in attributes:
                    values = getattr(section_filter, filter_attribute, None)
                    if values:
                        if query_type == "terms":
                            section_filter_must.append({"terms": {query_attribute: list(values)}})
                        elif query_type == "type":
                            if len(values) > 1:
                                section_filter_must.append(
                                    {'bool': {'should': [{'type': {'value': t}} for t in values]}})
                            else:
                                section_filter_must.append({"type": {"value": list(values)[0]}})
                        else:
                            raise ValueError("Unknown query type")
                if section_filter_must:
                    if len(section_filter_must) > 1:
                        section_should.append({'bool': {'must': section_filter_must}})
                    else:
                        section_should.append(section_filter_must[0])
            if section_should:
                if len(section_should) > 1:
                    query_filter.append({'bool': {'should': section_should}})
                else:
                    query_filter.append(section_should[0])

        # payload filters
        # PB attributes prefixes by event type in ES
        # we must use a query string for the field name wildcard

        payload_should = []
        for payload_filter in probe.payload_filters:
            payload_filter_must = []
            for attribute, values in payload_filter.items.items():
                if values:

                    def make_query_string(v):
                        return {'query_string': {'fields': ['*.{}'.format(attribute)],
                                                 'query': '"{}"'.format(v)}}
                    if len(values) > 1:
                        # TODO: escape value in query string
                        payload_filter_must.append({'bool': {'should': [make_query_string(v) for v in values]}})
                    else:
                        v = list(values)[0]
                        payload_filter_must.append(make_query_string(v))
            if payload_filter_must:
                if len(payload_filter_must) > 1:
                    payload_should.append({'bool': {'must': payload_filter_must}})
                else:
                    payload_should.append(payload_filter_must[0])
        if payload_should:
            if len(payload_should) > 1:
                query_filter.append({'bool': {'should': payload_should}})
            else:
                query_filter.append(payload_should[0])

        # search dict

        if search_dict:
            event_type = search_dict.pop('event_type')
            for attribute, values in search_dict.items():
                attribute = "{et}.{attr}".format(et=event_type, attr=attribute)
                if not values:
                    continue
                if not isinstance(values, list):
                    values = [values]
                if attribute.endswith('__startswith'):
                    attribute = attribute.replace('__startswith', '')
                    if len(values) > 1:
                        query_filter.append({'bool': {'should': [{'prefix': {attribute: v}} for v in values]}})
                    else:
                        query_filter.append({'prefix': {attribute: values[0]}})
                elif attribute.endswith('__regexp'):
                    attribute = attribute.replace('__regexp', '')
                    if len(values) > 1:
                        query_filter.append({'bool': {'should': [{'regexp': {attribute: v}} for v in values]}})
                    else:
                        query_filter.append({'regexp': {attribute: values[0]}})
                else:
                    if len(values) > 1:
                        query_filter.append({'terms': {attribute: values}})
                    else:
                        query_filter.append({'term': {attribute: values[0]}})

        return {'query': {'bool': {'filter': query_filter}}}

    def probe_events_count(self, probe, **search_dict):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_probe_events_body(probe, **search_dict)
        body['size'] = 0
        r = self._es.search(index=self.index, body=body)
        return r['hits']['total']

    def probe_events_fetch(self, probe, offset=0, limit=0, **search_dict):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_probe_events_body(probe, **search_dict)
        if offset:
            body['from'] = offset
        if limit:
            body['size'] = limit
        body['sort'] = [{'created_at': 'desc'}]
        r = self._es.search(index=self.index, body=body)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_type'], hit['_source'])

    def get_vis_url(self, probe, **search_dict):
        if not self.kibana_base_url:
            return
        body = self._get_probe_events_body(probe, **search_dict)
        kibana_params = {
            "columns": ["_source"],
            "index": self.index,
            "interval": "auto",
            "query": body["query"],
            "sort": ["created_at", "desc"]
        }
        query = {"_g": "()",  # rison for []
                 "_a": rison_dumps(kibana_params)}
        return "{kibana_base_url}#/discover?{query}".format(
                   kibana_base_url=self.kibana_base_url,
                   query=urllib.parse.urlencode(query, safe='/:,')
               )

    # apps hist data

    def _get_hist_query_dict(self, interval, bucket_number, tag, event_type):
        filter_list = []
        if tag:
            filter_list.append({"term": {"tags": tag}})
        if event_type:
            filter_list.append({"type": {"value": event_type}})
        interval_unit = self.INTERVAL_UNIT[interval]
        gte_range = "now-{q}{u}/{u}".format(q=bucket_number - 1,
                                            u=interval_unit)
        lt_range = "now+1{u}/{u}".format(u=interval_unit)
        filter_list.append({"range": {"created_at": {"gte": gte_range, "lt": lt_range}}})
        return {"bool": {"filter": filter_list}}

    def _get_hist_date_histogram_dict(self, interval, bucket_number):
        interval_unit = self.INTERVAL_UNIT[interval]
        min_bound = "now-{q}{u}/{u}".format(q=bucket_number - 1,
                                            u=interval_unit)
        max_bound = "now/{u}".format(u=interval_unit)
        return {"field": "created_at",
                "interval": interval,
                "min_doc_count": 0,
                "extended_bounds": {
                  "min": min_bound,
                  "max": max_bound
                }}

    def get_app_hist_data(self, interval, bucket_number, tag=None, event_type=None):
        body = {"query": self._get_hist_query_dict(interval, bucket_number, tag, event_type),
                "size": 0,
                "aggs": {
                  "buckets": {
                    "date_histogram": self._get_hist_date_histogram_dict(interval, bucket_number),
                    "aggs": {
                      "unique_msn": {
                        "cardinality": {
                          "field": "machine_serial_number",
                          "missing": 0
                        }
                      }
                    }
                  }
                }}
        r = self._es.search(index=self.index, body=body)
        return [(parser.parse(b["key_as_string"]), b["doc_count"], b["unique_msn"]["value"])
                for b in r['aggregations']['buckets']['buckets']]

    def close(self):
        for connection in self._es.transport.connection_pool.connections:
            if hasattr(connection, 'pool'):
                connection.pool.close()
