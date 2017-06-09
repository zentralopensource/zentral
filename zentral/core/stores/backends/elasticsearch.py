import logging
import random
import time
import urllib.parse
from dateutil import parser
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch.exceptions import ConnectionError, RequestError
from zentral.core.events import event_from_event_d, event_tags, event_types
from zentral.core.stores.backends.base import BaseEventStore
from zentral.utils.rison import dumps as rison_dumps
from requests_aws4auth import AWS4Auth

logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')

try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


class EventStore(BaseEventStore):
    MAX_CONNECTION_ATTEMPTS = 20
    INDEX_CONF = {
        "settings": {
            "number_of_shards": 1
        },
        "mappings": {
            "_default_": {
                "dynamic_templates": [
                    {"zentral_ip_address": {
                        "mapping": {"type": "ip"},
                        "match": "*ip_address"
                    }},
                    {"zentral_string_default": {
                        "mapping": {"type": "keyword",
                                    "ignore_above": 512},
                        "match": "*",
                        "unmatch": "*ip_address",
                        "match_mapping_type": "string"
                    }}
                ],
                "properties": {
                    "created_at": {
                        "type": "date"
                    },
                    "request": {
                        "properties": {
                            "ip": {"type": "ip"}
                        }
                    }
                }
            },
            "osquery_distributed_query_result": {
                "properties": {
                    "osquery_distributed_query_result": {
                        "properties": {
                            "result": {"enabled": False}
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
        auth = config_d.get("auth", {})
        if auth.get("auth_id") and auth.get("auth_key") and auth.get("region"):
            awsauth = AWS4Auth(auth['auth_id'], auth['auth_key'],
                               auth['region'], 'es')

            # this could break if you mix https and non-https servers
            use_ssl = config_d['servers'][0].startswith("https://")

            self._es = Elasticsearch(
                hosts=config_d['servers'],
                http_auth=awsauth,
                use_ssl=use_ssl, verify_certs=use_ssl,
                connection_class=RequestsHttpConnection
                )
        else:
            self._es = Elasticsearch(config_d['servers'])

        self.index = config_d['index']
        self.read_index = config_d.get('read_index', self.index)
        self.kibana_base_url = config_d.get('kibana_base_url', None)
        self.INDEX_CONF["settings"]["number_of_shards"] = config_d.get("number_of_shards", 1)
        self.test = test

    def wait_and_configure(self):
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            # get or create index
            try:
                if not self._es.indices.exists(self.index):
                    self._es.indices.create(self.index, body=self.INDEX_CONF)
                    logger.info("Index %s created", self.index)
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
            # wait for index recovery
            while True:
                recovery = self._es.indices.get(self.index, feature="_recovery")
                shards = recovery.get(self.index, {}).get("shards", [])
                if any(c["stage"] != "DONE" for c in shards):
                    s = 1000 / random.randint(1000, 3000)
                    time.sleep(s)
                    logger.warning("Elasticsearch index recovering")
                else:
                    logger.warning("Elasticsearch index recovery done")
                    break
            self.configured = True
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
        self.wait_and_configure_if_necessary()
        if isinstance(event, dict):
            event = event_from_event_d(event)
        doc_type, body = self._serialize_event(event)
        try:
            self._es.index(index=self.index, doc_type=doc_type, body=body)
            if self.test:
                self._es.indices.refresh(self.index)
        except:
            logger.exception('Could not add event to elasticsearch index')

    # machine events

    def _get_machine_events_body(self, machine_serial_number, event_type=None, tag=None):
        self.wait_and_configure_if_necessary()
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
        if tag:
            body['query']['bool']['filter'].append({'term': {'tags': tag}})
        return body

    def machine_events_count(self, machine_serial_number, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(machine_serial_number, event_type)
        body['size'] = 0
        r = self._es.search(index=self.read_index, body=body)
        return r['hits']['total']

    def machine_events_fetch(self, machine_serial_number, offset=0, limit=0, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(machine_serial_number, event_type)
        if offset:
            body['from'] = offset
        if limit:
            body['size'] = limit
        body['sort'] = [{'created_at': 'desc'}]
        r = self._es.search(index=self.read_index, body=body)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_type'], hit['_source'])

    def machine_events_types_with_usage(self, machine_serial_number):
        body = self._get_machine_events_body(machine_serial_number)
        body.update({
            'size': 0,
            'aggs': {
                'doc_types': {
                    'terms': {
                        'field': '_type',
                        'size': len(event_types)
                    }
                }
            }
        })
        r = self._es.search(index=self.read_index, body=body)
        types_d = {}
        for bucket in r['aggregations']['doc_types']['buckets']:
            types_d[bucket['key']] = bucket['doc_count']
        return types_d

    def get_last_machine_heartbeats(self, machine_serial_number):
        body = self._get_machine_events_body(machine_serial_number, tag="heartbeat")
        body.update({
            'size': 0,
            'aggs': {
                'inventory_heartbeats': {
                    'filter': {'type': {'value': 'inventory_heartbeat'}},
                    'aggs': {
                        'sources': {
                            'terms': {
                                'field': 'inventory_heartbeat.source.name',
                                'size': 10  # TODO: HARDCODED
                            },
                            'aggs': {
                                'max_created_at': {
                                    'max': {
                                        'field': 'created_at'
                                    }
                                }
                            }
                        }
                    }
                },
                'other_events': {
                    'filter': {'bool': {'must_not': {'type': {'value': 'inventory_heartbeat'}}}},
                    'aggs': {
                        'event_types': {
                            'terms': {
                                'field': '_type',
                                'size': len([et for et in event_types.values()
                                             if 'heartbeat' in et.tags])
                            },
                            'aggs': {
                                'max_created_at': {
                                    'max': {
                                        'field': 'created_at'
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
        r = self._es.search(index=self.read_index, body=body)
        heartbeats = []
        for bucket in r["aggregations"]["inventory_heartbeats"]["sources"]["buckets"]:
            heartbeats.append((event_types["inventory_heartbeat"],
                               bucket["key"],
                               parser.parse(bucket["max_created_at"]["value_as_string"])))
        for bucket in r["aggregations"]["other_events"]["event_types"]["buckets"]:
            event_type = bucket["key"]
            event_type_class = event_types.get(event_type, None)
            if not event_type_class:
                logger.error("Unknown event type %s", event_type)
            else:
                heartbeats.append((event_type_class,
                                   None,
                                   parser.parse(bucket["max_created_at"]["value_as_string"])))
        return heartbeats

    # probe events

    def _get_probe_events_body(self, probe, **search_dict):
        self.wait_and_configure_if_necessary()
        # TODO: doc, better args, ...
        query_filter = []

        # inventory and metadata filters
        seen_event_types = set([])
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
                        if section == "metadata":
                            if filter_attribute == "event_types":
                                seen_event_types.update(values)
                            elif filter_attribute == "event_tags":
                                seen_event_types.update(event_cls.event_type
                                                        for v in values
                                                        for event_cls in event_tags.get(v, []))
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
        # PB attributes prefixed by event type in ES
        # we must try all possible prefixes
        if seen_event_types:
            # We are lucky, we only have to test some prefixes
            # because there is at least one metadata filter with an event type or a tag.
            payload_event_types_for_filters = seen_event_types
        else:
            # Bad luck, no metadata filter. We must try all event types.
            payload_event_types_for_filters = event_types.keys()

        payload_should = []
        for payload_filter in probe.payload_filters:
            payload_filter_must = []
            for attribute, values in payload_filter.items.items():
                if values:

                    def make_query_string(v):
                        return {'query_string': {'fields': ['{}.{}'.format(event_type, attribute)
                                                            for event_type in payload_event_types_for_filters],
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
        r = self._es.search(index=self.read_index, body=body)
        return r['hits']['total']

    def probe_events_aggregations(self, probe, **search_dict):
        body = self._get_probe_events_body(probe, **search_dict)
        body['size'] = 0
        aggs = {}
        aggregations = probe.get_aggregations()
        for field, aggregation in aggregations.items():
            a_type = aggregation["type"]
            bucket_number = aggregation["bucket_number"]
            event_type = aggregation.get("event_type")
            es_field = ".".join(s for s in (event_type, field) if s)
            if a_type == "terms":
                aggs[field] = {
                    "terms": {
                        "field": es_field,
                        "size": bucket_number
                    }
                }
            elif a_type == "table":
                def add_terms(agg, fields, agg_key=None):
                    es_fn = "{}.{}".format(event_type, fields.pop(0))
                    key = agg_key or es_fn
                    agg.update({
                        key: {
                            "terms": {
                                "field": es_fn,
                                "size": bucket_number
                            }
                        }
                    })
                    if fields:
                        agg[key]["aggs"] = {}
                        add_terms(agg[key]["aggs"], fields)
                add_terms(aggs,
                          [fn for fn, _ in aggregation["columns"]],
                          field)
            elif a_type == "date_histogram":
                aggs[field] = {
                    "date_histogram": self._get_hist_date_histogram_dict(
                        aggregation["interval"],
                        bucket_number,
                        es_field
                    )
                }
            else:
                logger.error("Unknown aggregation type %s", a_type)
        body["aggs"] = aggs
        r = self._es.search(index=self.read_index, body=body)
        results = {}
        for field, agg_result in r["aggregations"].items():
            aggregation = aggregations[field]
            interval = aggregation.get("interval")
            a_type = aggregation["type"]
            buckets = agg_result["buckets"]
            if a_type == "table":
                columns = aggregation["columns"]

                def yield_bucket_values(agg_result, fn_list, value_d=None):
                    if value_d is None:
                        value_d = {}
                    buckets = agg_result["buckets"]
                    fn_list = list(fn_list)
                    current_fn = fn_list.pop(0)
                    for bucket in buckets:
                        bucket_value_d = value_d.copy()
                        bucket_value_d[current_fn] = bucket["key"]
                        if fn_list:
                            next_fn = fn_list[0]
                            yield from yield_bucket_values(bucket["{}.{}".format(event_type, next_fn)],
                                                           fn_list, bucket_value_d)
                        else:
                            bucket_value_d["event_count"] = bucket["doc_count"]
                            yield bucket_value_d
                    sum_other_doc_count = agg_result.pop("sum_other_doc_count", 0)
                    if sum_other_doc_count:
                        other_doc_value_d = value_d.copy()
                        other_doc_value_d[current_fn] = "…"
                        for other_fn in fn_list:
                            other_doc_value_d[other_fn] = "…"
                        other_doc_value_d["event_count"] = sum_other_doc_count
                        yield other_doc_value_d

                values = list(yield_bucket_values(agg_result, [fn for fn, _ in columns]))
            elif a_type == "terms":
                values = [(b["key"], b["doc_count"]) for b in buckets]
                sum_other_doc_count = agg_result.get("sum_other_doc_count")
                if sum_other_doc_count:
                    values.append((None, sum_other_doc_count))
            elif a_type == "date_histogram":
                bucket_number = aggregation["bucket_number"]
                values = [(parser.parse(b["key_as_string"]), b["doc_count"])
                          for b in buckets[-1 * bucket_number:]]
            results[field] = {"label": aggregation.get("label", field.capitalize()),
                              "type": a_type,
                              "values": values}
            if interval:
                results[field]["interval"] = interval
        return results

    def probe_events_fetch(self, probe, offset=0, limit=0, **search_dict):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_probe_events_body(probe, **search_dict)
        if offset:
            body['from'] = offset
        if limit:
            body['size'] = limit
        body['sort'] = [{'created_at': 'desc'}]
        r = self._es.search(index=self.read_index, body=body)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_type'], hit['_source'])

    def get_vis_url(self, probe, **search_dict):
        if not self.kibana_base_url:
            return
        body = self._get_probe_events_body(probe, **search_dict)
        kibana_params = {
            "columns": ["_source"],
            "index": self.read_index,
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
            if isinstance(event_type, list):
                filter_list.append({"bool": {
                                        "should": [
                                            {"type": {"value": et}}
                                            for et in event_type
                                        ]
                                    }})
            else:
                filter_list.append({"type": {"value": event_type}})
        interval_unit = self.INTERVAL_UNIT[interval]
        gte_range = "now-{q}{u}/{u}".format(q=bucket_number - 1,
                                            u=interval_unit)
        lt_range = "now+1{u}/{u}".format(u=interval_unit)
        filter_list.append({"range": {"created_at": {"gte": gte_range, "lt": lt_range}}})
        return {"bool": {"filter": filter_list}}

    def _get_hist_date_histogram_dict(self, interval, bucket_number, field="created_at"):
        interval_unit = self.INTERVAL_UNIT[interval]
        min_bound = "now-{q}{u}/{u}".format(q=bucket_number - 1,
                                            u=interval_unit)
        max_bound = "now/{u}".format(u=interval_unit)
        return {"field": field,
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
        self.wait_and_configure_if_necessary()
        r = self._es.search(index=self.read_index, body=body)
        return [(parser.parse(b["key_as_string"]), b["doc_count"], b["unique_msn"]["value"])
                for b in r['aggregations']['buckets']['buckets']]

    def close(self):
        for connection in self._es.transport.connection_pool.connections:
            if hasattr(connection, 'pool'):
                connection.pool.close()
