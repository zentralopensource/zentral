from itertools import product
import logging
import random
import time
from urllib.parse import urlencode, urljoin, urlparse
from dateutil import parser
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch.helpers import streaming_bulk
from elasticsearch.exceptions import ConnectionError, RequestError
from zentral.core.events import event_from_event_d, event_tags, event_types
from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.probes.base import PayloadFilter
from zentral.core.stores.backends.base import BaseEventStore
from zentral.utils.rison import dumps as rison_dumps

logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')

try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


class EventStore(BaseEventStore):
    max_batch_size = 500
    machine_events = True
    last_machine_heartbeats = True

    LEGACY_DOC_TYPE = "doc"  # _type used with 5.6 < ES < 7
    MAX_CONNECTION_ATTEMPTS = 20
    MAPPINGS = {
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
            "type": {
                "type": "keyword"
            },
            "created_at": {
                "type": "date"
            },
            "request": {
                "properties": {
                    "ip": {"type": "ip"},
                    "geo": {
                        "properties": {
                            "location": {"type": "geo_point"}
                        }
                    }
                }
            },
            "osquery_distributed_query_result": {
                "properties": {
                    "result": {"enabled": False}
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
        # es kwargs
        kwargs = {}

        # es kwargs > hosts
        hosts = []
        configured_hosts = config_d.get("hosts", config_d.get("servers"))
        for host in configured_hosts:
            if not isinstance(host, dict):
                o = urlparse(host)
                host = {k: v for k, v in (('host', o.hostname),
                                          ('port', o.port),
                                          ('url_prefix', o.path)) if v}
                if o.scheme == "https" or o.port == 443:
                    if o.port is None:
                        host['port'] = 443
                    host['use_ssl'] = True
            hosts.append(host)
        kwargs['hosts'] = hosts

        # es kwargs > verify_certs
        if any(host.get("use_ssl") for host in hosts):
            kwargs['verify_certs'] = True

        # es kwargs > http_auth (for AWS)
        aws_auth = config_d.get("aws_auth")
        if aws_auth:
            kwargs["connection_class"] = RequestsHttpConnection
            try:
                from requests_aws4auth import AWS4Auth
                kwargs['http_auth'] = AWS4Auth(aws_auth['access_id'],
                                               aws_auth['secret_key'],
                                               aws_auth['region'],
                                               'es')
            except ImportError:
                raise ImproperlyConfigured("Missing requests_aws4auth pip dependency "
                                           "for ES AWS credentials")
            except KeyError:
                raise ImproperlyConfigured("access_id, secret_key or region missing "
                                           "in aws_auth config")

        self._es = Elasticsearch(**kwargs)
        self.use_mapping_types = None

        self.index = config_d['index']
        self.read_index = config_d.get('read_index', self.index)
        self.kibana_discover_url = config_d.get('kibana_discover_url')
        if not self.kibana_discover_url:
            # TODO deprecated. Remove.
            kibana_base_url = config_d.get('kibana_base_url')
            if kibana_base_url:
                self.kibana_discover_url = urljoin(kibana_base_url, "app/discover#/")
        if self.kibana_discover_url:
            self.machine_events_url = True
        self.kibana_index_pattern_uuid = config_d.get('kibana_index_pattern_uuid')
        self.index_settings = {
            "index.mapping.total_fields.limit": config_d.get("index.mapping.total_fields.limit", 2000),
            "number_of_shards": config_d.get("number_of_shards", 1),
            "number_of_replicas": config_d.get("number_of_replicas", 0)
        }
        self.test = test
        self.version = None

    def get_index_conf(self):
        if self.version:
            if self.version >= [7]:
                return {"settings": self.index_settings,
                        "mappings": self.MAPPINGS}
            else:
                return {"settings": self.index_settings,
                        "mappings": {self.LEGACY_DOC_TYPE: self.MAPPINGS}}

    def wait_and_configure(self):
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            # get or create index
            try:
                info = self._es.info()
                self.version = [int(i) for i in info["version"]["number"].split(".")]
                if not self._es.indices.exists(self.index):
                    self._es.indices.create(self.index, body=self.get_index_conf())
                    self.use_mapping_types = False
                    logger.info("Index %s created", self.index)
            except ConnectionError:
                s = (i + 1) * random.uniform(0.9, 1.1)
                logger.warning('Could not connect to server %d/%d. Sleep %ss',
                               i + 1, self.MAX_CONNECTION_ATTEMPTS, s)
                time.sleep(s)
                continue
            except RequestError as exception:
                error = exception.error.lower()
                if "already" in error and "exist" in error:
                    # race
                    logger.info('Index %s exists', self.index)
                else:
                    raise
            # wait for index recovery
            waiting_for_recovery = False
            while True:
                recovery = self._es.indices.recovery(self.index, params={"active_only": "true"})
                shards = recovery.get(self.index, {}).get("shards", [])
                if any(c["stage"] != "DONE" for c in shards):
                    waiting_for_recovery = True
                    s = 1000 / random.randint(1000, 3000)
                    time.sleep(s)
                    logger.warning("Elasticsearch index recovering")
                else:
                    if waiting_for_recovery:
                        logger.warning("Elasticsearch index recovery done")
                    break
            self.configured = True
            break
        else:
            raise Exception('Could not connect to server')

        # use_mapping_types
        if self.use_mapping_types is None:
            if self.version >= [7]:
                self.use_mapping_types = False
            else:
                mappings = set(list(self._es.indices.get_mapping(self.index).values())[0]['mappings'])
                self.use_mapping_types = self.LEGACY_DOC_TYPE not in mappings

    def _get_type_field(self):
        if not self.use_mapping_types:
            return "type"
        else:
            return "_type"

    def _get_type_filter(self, event_type):
        if not self.use_mapping_types:
            return {"term": {"type": event_type}}
        else:
            return {"type": {"value": event_type}}

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        es_event_d = event_d.pop('_zentral')
        if not self.use_mapping_types:
            event_type = es_event_d['type']
            es_doc_type = self.LEGACY_DOC_TYPE
        else:
            event_type = es_event_d.pop('type')
            es_doc_type = event_type  # document type in ES
        es_event_d[event_type] = event_d
        return es_doc_type, es_event_d

    def _deserialize_event(self, es_doc_type, es_event_d):
        if es_doc_type == "_doc" or es_doc_type == self.LEGACY_DOC_TYPE:
            event_type = es_event_d["type"]
        else:
            event_type = es_doc_type
            es_event_d["type"] = event_type
        event_d = es_event_d.pop(event_type, {})
        event_d['_zentral'] = es_event_d
        return event_from_event_d(event_d)

    def store(self, event):
        self.wait_and_configure_if_necessary()
        doc_type, body = self._serialize_event(event)
        kwargs = {"body": body}
        if self.version < [7]:
            kwargs["doc_type"] = doc_type
        self._es.index(index=self.index, **kwargs)
        if self.test:
            self._es.indices.refresh(self.index)

    def bulk_store(self, events):
        self.wait_and_configure_if_necessary()
        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")
        if self.version < [7]:
            raise RuntimeError("bulk_store is not available for elasticsearch < 7")

        ID_SEP = "_"

        def iter_actions():
            for event in events:
                _, doc = self._serialize_event(event)
                doc.update({"_index": self.index, "_id": f'{doc["id"]}{ID_SEP}{doc["index"]}'})
                yield doc

        for ok, item in streaming_bulk(self._es, iter_actions(),
                                       chunk_size=self.batch_size,
                                       raise_on_error=False, raise_on_exception=False,
                                       max_retries=2
                                       ):
            if ok:
                try:
                    event_id, event_index = item["index"]["_id"].split(ID_SEP)
                    yield event_id, int(event_index)
                except (KeyError, ValueError):
                    logger.error("could not yield indexed event key")

    def _build_kibana_url(self, body, from_dt=None, to_dt=None):
        if not self.kibana_discover_url:
            return
        kibana_params = {
            "columns": ["_source"],
            "interval": "auto",
            "query": {"language": "lucene", "query": body["query"]},
            "sort": ["created_at", "desc"]
        }
        if self.kibana_index_pattern_uuid:
            kibana_params["index"] = self.kibana_index_pattern_uuid
        time_d = {"from": "now-6h", "to": "now"}
        if from_dt:
            time_d["from"] = from_dt.isoformat()
        if to_dt:
            time_d["to"] = to_dt.isoformat()
        query = {"_g": rison_dumps({"time": time_d}),
                 "_a": rison_dumps(kibana_params)}
        return "{base_url}?{query}".format(
                   base_url=self.kibana_discover_url,
                   query=urlencode(query, safe='/:,')
               )

    # machine events

    def _get_machine_events_body(self, serial_number, from_dt=None, to_dt=None, event_type=None, tag=None):
        self.wait_and_configure_if_necessary()
        filters = [
            {'term': {'machine_serial_number': serial_number}},
        ]
        range_kwargs = {}
        if from_dt:
            range_kwargs["gte"] = from_dt
        if to_dt:
            range_kwargs["lte"] = to_dt
        if range_kwargs:
            filters.append({'range': {'created_at': range_kwargs}})
        if event_type:
            filters.append(self._get_type_filter(event_type))
        if tag:
            filters.append({'term': {'tags': tag}})
        return {'query': {'bool': {'filter': filters}}}

    def get_total_machine_event_count(self, serial_number, from_dt, to_dt=None, event_type=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(serial_number, from_dt, to_dt, event_type)
        body['size'] = 0
        body['track_total_hits'] = True
        r = self._es.search(index=self.read_index, body=body)
        total = r['hits']['total']
        if isinstance(total, dict):  # ES >= 7
            return total["value"]
        else:
            return total

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_machine_events_body(serial_number, from_dt, to_dt, event_type)
        body['sort'] = [
            {'created_at': 'desc'},
            {'id': 'asc'},  # tie breakers
            {'index': 'asc'}  # tie breakers
        ]
        if limit:
            body['size'] = limit
        if cursor:
            body['search_after'] = cursor
        r = self._es.search(index=self.read_index, body=body)
        events = []
        next_cursor = None
        for hit in r['hits']['hits']:
            events.append(self._deserialize_event(hit['_type'], hit['_source']))
            next_cursor = hit.pop("sort", None)
        if len(events) < limit:
            next_cursor = None
        return events, next_cursor

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        body = self._get_machine_events_body(serial_number, from_dt, to_dt)
        body.update({
            'size': 0,
            'aggs': {
                'event_types': {
                    'terms': {
                        'field': self._get_type_field(),
                        'size': len(event_types)
                    }
                }
            }
        })
        r = self._es.search(index=self.read_index, body=body)
        types_d = {}
        for bucket in r['aggregations']['event_types']['buckets']:
            types_d[bucket['key']] = bucket['doc_count']
        return types_d

    def get_last_machine_heartbeats(self, serial_number, from_dt):
        body = self._get_machine_events_body(serial_number, from_dt, tag="heartbeat")
        body.update({
            'size': 0,
            'aggs': {
                'inventory_heartbeats': {
                    'filter': self._get_type_filter('inventory_heartbeat'),
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
                    'filter': {'bool': {'must_not': self._get_type_filter('inventory_heartbeat')}},
                    'aggs': {
                        'event_types': {
                            'terms': {
                                'field': self._get_type_field(),
                                'size': len([et for et in event_types.values()
                                             if 'heartbeat' in et.tags])
                            },
                            'aggs': {
                                'user_agents': {
                                    'terms': {
                                        'field': 'request.user_agent',
                                        'size': 100,
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
                }
            }
        })
        r = self._es.search(index=self.read_index, body=body)
        heartbeats = []
        for bucket in r["aggregations"]["inventory_heartbeats"]["sources"]["buckets"]:
            heartbeats.append((event_types["inventory_heartbeat"],
                               bucket["key"],
                               [(None, parser.parse(bucket["max_created_at"]["value_as_string"]))]))
        for bucket in r["aggregations"]["other_events"]["event_types"]["buckets"]:
            event_type = bucket["key"]
            event_type_class = event_types.get(event_type, None)
            if not event_type_class:
                logger.error("Unknown event type %s", event_type)
            else:
                ua_list = []
                for sub_bucket in bucket["user_agents"]["buckets"]:
                    ua = sub_bucket["key"]
                    ua_list.append((ua, parser.parse(sub_bucket["max_created_at"]["value_as_string"])))
                heartbeats.append((event_type_class, None, ua_list))
        return heartbeats

    def get_machine_events_url(self, serial_number, from_dt, to_dt=None, event_type=None):
        return self._build_kibana_url(
            self._get_machine_events_body(serial_number, event_type=event_type),
            from_dt, to_dt
        )

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
                                    {'bool': {'should': [self._get_type_filter(t) for t in values]}}
                                )
                            else:
                                section_filter_must.append(self._get_type_filter(list(values)[0]))
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
            for attribute, operator, values in payload_filter.items:
                # the values may be casted to booleans if the field is stored as a boolean field in elasticsearch
                # only json like boolean strings will be automatically interpreted as booleans
                processed_values = [v.lower() if v in ("False", "True") else v for v in values]
                attribute_queries = [{"term": {"{}.{}".format(event_type, attribute): value}}
                                     for event_type, value in product(payload_event_types_for_filters,
                                                                      processed_values)]
                if len(attribute_queries) > 1:
                    # OR for the different values
                    if operator == PayloadFilter.IN:
                        bool_attr = "should"
                    elif operator == PayloadFilter.NOT_IN:
                        bool_attr = "must_not"
                    payload_filter_must.append({'bool': {bool_attr: attribute_queries}})
                else:
                    attribute_query = attribute_queries[0]
                    if operator == PayloadFilter.NOT_IN:
                        attribute_query = {'bool': {'must_not': attribute_query}}
                    payload_filter_must.append(attribute_query)
            if payload_filter_must:
                # AND for the attributes of the same payload filter
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

                if values is None:
                    continue

                if not isinstance(values, list):
                    values = [values]
                elif not values:
                    continue

                if attribute.endswith('__startswith'):
                    attribute = attribute.replace('__startswith', '')
                    if len(values) > 1:
                        sub_query_filter = {'bool': {'should': [{'prefix': {attribute: v}} for v in values]}}
                    else:
                        sub_query_filter = {'prefix': {attribute: values[0]}}
                elif attribute.endswith('__regexp'):
                    attribute = attribute.replace('__regexp', '')
                    if len(values) > 1:
                        sub_query_filter = {'bool': {'should': [{'regexp': {attribute: v}} for v in values]}}
                    else:
                        sub_query_filter = {'regexp': {attribute: values[0]}}
                else:
                    if len(values) > 1:
                        sub_query_filter = {'terms': {attribute: values}}
                    else:
                        sub_query_filter = {'term': {attribute: values[0]}}

                query_filter.append(sub_query_filter)

        return {'query': {'bool': {'filter': query_filter}}}

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

    def probe_events_count(self, probe, **search_dict):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_probe_events_body(probe, **search_dict)
        body['size'] = 0
        body['track_total_hits'] = True
        r = self._es.search(index=self.read_index, body=body)
        total = r['hits']['total']
        if isinstance(total, dict):  # ES >= 7
            return total["value"]
        else:
            return total

    def probe_events_aggregations(self, probe, **search_dict):
        body = self._get_probe_events_body(probe, **search_dict)
        body['size'] = 0
        aggs = {}
        aggregations = probe.get_aggregations()
        for field, aggregation in aggregations.items():
            a_type = aggregation["type"]
            bucket_number = aggregation["bucket_number"]
            event_type = aggregation.get("event_type")
            if field == "event_type":
                es_field = self._get_type_field()
            else:
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

    def get_vis_url(self, probe, **search_dict):
        return self._build_kibana_url(self._get_probe_events_body(probe, **search_dict))

    # incident events

    def _get_incident_events_body(self, incident):
        # see incident and machine incident serialization in zentral.core.incidents.models
        self.wait_and_configure_if_necessary()
        return {
            'query': {
                'bool': {
                    'filter': [
                        {'bool': {
                            'should': [
                                # incidents present in triggering event metadata
                                {'term': {'incidents.pk': incident.pk}},
                                # incident events, pk attribute
                                {'term': {'incident.pk': incident.pk}},
                                # machine incident events, incident.pk attribute
                                {'term': {'machine_incident.incident.pk': incident.pk}}
                            ]
                        }}
                    ]
                }
            }
        }

    def incident_events_count(self, incident):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_incident_events_body(incident)
        body['size'] = 0
        body['track_total_hits'] = True
        r = self._es.search(index=self.read_index, body=body)
        total = r['hits']['total']
        if isinstance(total, dict):  # ES >= 7
            return total["value"]
        else:
            return total

    def incident_events_fetch(self, probe, offset=0, limit=0, **search_dict):
        # TODO: count could work from first fetch with elasticsearch.
        body = self._get_incident_events_body(probe, **search_dict)
        if offset:
            body['from'] = offset
        if limit:
            body['size'] = limit
        body['sort'] = [{'created_at': 'desc'}]
        r = self._es.search(index=self.read_index, body=body)
        for hit in r['hits']['hits']:
            yield self._deserialize_event(hit['_type'], hit['_source'])

    def get_incident_vis_url(self, incident):
        return self._build_kibana_url(self._get_incident_events_body(incident))

    # zentral apps data

    def _get_hist_query_dict(self, interval, bucket_number, tag, event_type):
        filter_list = []
        if tag:
            filter_list.append({"term": {"tags": tag}})
        if event_type:
            if isinstance(event_type, list):
                filter_list.append({"bool": {
                                        "should": [
                                            self._get_type_filter(et)
                                            for et in event_type
                                        ]
                                    }})
            else:
                filter_list.append(self._get_type_filter(event_type))
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
        if self.version >= [7, 2]:
            interval_attr = "calendar_interval"
        else:
            interval_attr = "interval"
        return {"field": field,
                interval_attr: interval,
                "min_doc_count": 0,
                "extended_bounds": {
                  "min": min_bound,
                  "max": max_bound
                }}

    def get_app_hist_data(self, interval, bucket_number, tag=None, event_type=None):
        self.wait_and_configure_if_necessary()
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
        r = self._es.search(index=self.read_index, body=body)
        return [(parser.parse(b["key_as_string"]), b["doc_count"], b["unique_msn"]["value"])
                for b in r['aggregations']['buckets']['buckets']]

    def close(self):
        for connection in self._es.transport.connection_pool.connections:
            if hasattr(connection, 'pool'):
                connection.pool.close()
