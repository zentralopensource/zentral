import logging
import os
import random
import time
from urllib.parse import urlencode
from dateutil import parser
from rest_framework import serializers
from zentral.core.events import event_from_event_d, event_types
from zentral.core.events.filter import EventFilterSet
from zentral.core.events.serializers import EventFilterSetSerializer
from zentral.core.stores.backends.base import BaseStore
from zentral.core.stores.backends.http import HTTPURLField
from zentral.utils.rison import dumps as rison_dumps

logger = logging.getLogger('zentral.core.stores.backends.es_os_base')

try:
    random = random.SystemRandom()
except NotImplementedError:
    logger.warning('No secure pseudo random number generator available.')


class ESOSStore(BaseStore):
    kwargs_keys = (
        "hosts",
        "verify_certs",
        "ssl_show_warn",
        "username",
        "password",
        "batch_size",
        "index",
        "indices",
        "read_index",
        "number_of_shards",
        "number_of_replicas",
        "kibana_discover_url",
        "kibana_index_pattern_uuid",
    )
    encrypted_kwargs_paths = (
        ["password"],
    )

    client_class = None
    streaming_bulk = None
    connection_error_class = Exception
    request_error_class = Exception

    total_fields_limit = 2000
    max_batch_size = 500
    machine_events = True
    last_machine_heartbeats = True
    object_events = True
    probe_events = True

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
             }},
        ],
        "properties": {
            "type": {
                "type": "keyword"
            },
            "created_at": {
                "type": "date"
            },
            "request": {
                "type": "object",
                "properties": {
                    "ip": {"type": "ip"},
                    "geo": {
                        "type": "object",
                        "properties": {
                            "location": {"type": "geo_point"}
                        }
                    }
                }
            },
            "munki_event": {
                "type": "object",
                "properties": {
                    "conditions": {
                        "type": "object",
                        "properties": {
                            "os_build_last_component": {
                                "type": "keyword"
                            }
                        }
                    }
                }
            },
            "zentral_audit": {
                "type": "object",
                "properties": {
                    "object": {
                        "type": "object",
                        "properties": {
                            "new_value": {
                                "type": "object",
                                "enabled": False,
                            },
                            "prev_value": {
                                "type": "object",
                                "enabled": False,
                            },
                        },
                    },
                },
            },
        }
    }
    INTERVAL_UNIT = {
        "hour": "h",
        "day": "d",
        "week": "w",
        "month": "M",
    }

    def _get_client_kwargs(self):
        client_kwargs = {
            "hosts": self.hosts,
            "verify_certs": self.verify_certs,
            "ssl_show_warn": self.ssl_show_warn,
        }
        if self.username and self.password:
            client_kwargs["http_auth"] = (self.username, self.password)
        return client_kwargs

    def load(self):
        super().load()
        # indices
        self.read_index = self.read_index or self.index
        self.index_mappings = None
        if self.indices:
            index_mappings = []
            for index in sorted(self.indices, key=lambda idx: idx["priority"], reverse=True):
                index_mappings.append((EventFilterSet.from_mapping(index), index["name"]))
            self.index_mappings = index_mappings

        # kibana
        if self.kibana_discover_url:
            self.machine_events_url = True
            self.object_events_url = True
            self.probe_events_url = True

        # backward compatibility
        self.version = None
        self.use_mapping_types = None

        # for the tests
        self.force_index_refresh = os.environ.get("ZENTRAL_FORCE_ES_OS_INDEX_REFRESH") == "1"

    def get_index_conf(self):
        index_settings = {
            "index.mapping.total_fields.limit": self.total_fields_limit,
            "number_of_shards": self.number_of_shards,
            "number_of_replicas": self.number_of_replicas,
        }
        if self.version:
            if self.version >= [7]:
                return {"settings": index_settings,
                        "mappings": self.MAPPINGS}
            else:
                return {"settings": index_settings,
                        "mappings": {self.LEGACY_DOC_TYPE: self.MAPPINGS}}

    def wait_and_configure(self):
        self._client = self.client_class(**self._get_client_kwargs())
        for i in range(self.MAX_CONNECTION_ATTEMPTS):
            # get or create index
            try:
                info = self._client.info()
                self.version = [int(i) for i in info["version"]["number"].split(".")]
                if self.index and not self._client.indices.exists(index=self.index):
                    self._client.indices.create(index=self.index, body=self.get_index_conf())
                    self.use_mapping_types = False
                    logger.info("Index %s created", self.index)
            except self.connection_error_class:
                s = (i + 1) * random.uniform(0.9, 1.1)
                logger.warning('Could not connect to server %d/%d. Sleep %ss',
                               i + 1, self.MAX_CONNECTION_ATTEMPTS, s)
                time.sleep(s)
                continue
            except self.request_error_class as exception:
                error = exception.error.lower()
                if "already" in error and "exist" in error:
                    # race
                    logger.info('Index %s exists', self.index)
                else:
                    raise
            if self.index:
                # wait for index recovery
                waiting_for_recovery = False
                while True:
                    recovery = self._client.indices.recovery(index=self.index, active_only=True)
                    shards = recovery.get(self.index, {}).get("shards", [])
                    if any(c["stage"] != "DONE" for c in shards):
                        waiting_for_recovery = True
                        s = 1000 / random.randint(1000, 3000)
                        time.sleep(s)
                        logger.warning("Index recovering")
                    else:
                        if waiting_for_recovery:
                            logger.warning("Index recovery done")
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
                mappings = set(
                    list(self._client.indices.get_mapping(index=self.index).values())[0]['mappings']
                )
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

    def _get_event_index(self, event_d):
        if self.index:
            return self.index
        else:
            for event_filter_set, index in self.index_mappings:
                if event_filter_set.match_serialized_event(event_d):
                    return index
        # should never happen, since we make sure that either index is set, or a default index mapping
        raise RuntimeError("No index found for event")

    def _serialize_event(self, event):
        if not isinstance(event, dict):
            event_d = event.serialize()
        else:
            event_d = event
        index = self._get_event_index(event_d)
        es_event_d = event_d.pop('_zentral')
        if not self.use_mapping_types:
            event_type = es_event_d['type']
            es_doc_type = self.LEGACY_DOC_TYPE
        else:
            event_type = es_event_d.pop('type')
            es_doc_type = event_type  # document type in ES
        namespace = es_event_d.get('namespace', event_type)
        es_event_d[namespace] = event_d
        return index, es_doc_type, es_event_d

    def _deserialize_event(self, es_doc_type, es_event_d):
        if es_doc_type is None or es_doc_type == "_doc" or es_doc_type == self.LEGACY_DOC_TYPE:
            event_type = es_event_d["type"]
        else:
            event_type = es_doc_type
            es_event_d["type"] = event_type
        namespace = es_event_d.get('namespace', event_type)
        event_d = es_event_d.pop(namespace, {})
        event_d['_zentral'] = es_event_d
        return event_from_event_d(event_d)

    def _streaming_bulk(self, *args, **kwargs):
        raise NotImplementedError

    def store(self, event):
        self.wait_and_configure_if_necessary()
        index, doc_type, body = self._serialize_event(event)
        kwargs = {"body": body}
        if self.version < [7]:
            kwargs["doc_type"] = doc_type
        self._client.index(index=index, **kwargs)
        if self.force_index_refresh:
            self._client.indices.refresh(index=index)

    def bulk_store(self, events):
        self.wait_and_configure_if_necessary()
        if self.batch_size < 2:
            raise RuntimeError("bulk_store is not available when batch_size < 2")
        if self.version < [7]:
            raise RuntimeError("bulk_store is not available for elasticsearch < 7")

        ID_SEP = "_"

        def iter_actions():
            for event in events:
                index, _, doc = self._serialize_event(event)
                doc.update({"_index": index, "_id": f'{doc["id"]}{ID_SEP}{doc["index"]}'})
                yield doc

        for ok, item in self._streaming_bulk(client=self._client,
                                             actions=iter_actions(),
                                             chunk_size=self.batch_size,
                                             raise_on_error=False, raise_on_exception=False,
                                             max_retries=2):
            try:
                event_id, event_index = item["index"]["_id"].split(ID_SEP)
                event_index = int(event_index)
            except (KeyError, ValueError):
                logger.error("could not get event id and index")
            else:
                if ok:
                    yield event_id, event_index
                else:
                    error = item["index"].get("error")
                    error_type = reason = None
                    if error:
                        if isinstance(error, dict):
                            error_type = error.get("type")
                            reason = error.get("reason")
                        elif isinstance(error, str):
                            reason = error
                        else:
                            reason = "UNKNOWN"
                    logger.error("could not index event %s %s: %s %s",
                                 event_id, event_index, error_type or "-", reason or "-")

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

    # base event methods

    def _fetch_events(self, body, limit=10, cursor=None):
        body['sort'] = [
            {'created_at': 'desc'},
            {'id': 'asc'},  # tie breakers
            {'index': 'asc'}  # tie breakers
        ]
        if limit:
            body['size'] = limit
        if cursor:
            body['search_after'] = cursor
        r = self._client.search(index=self.read_index, body=body)
        events = []
        next_cursor = None
        for hit in r['hits']['hits']:
            events.append(self._deserialize_event(hit.get('_type'), hit['_source']))
            next_cursor = hit.pop("sort", None)
        if len(events) < limit:
            next_cursor = None
        return events, next_cursor

    def _get_aggregated_event_counts(self, body):
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
        r = self._client.search(index=self.read_index, body=body)
        types_d = {}
        for bucket in r['aggregations']['event_types']['buckets']:
            types_d[bucket['key']] = bucket['doc_count']
        return types_d

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
            range_kwargs["lt"] = to_dt
        if range_kwargs:
            filters.append({'range': {'created_at': range_kwargs}})
        if event_type:
            filters.append(self._get_type_filter(event_type))
        if tag:
            filters.append({'term': {'tags': tag}})
        return {'query': {'bool': {'filter': filters}}}

    def fetch_machine_events(self, serial_number, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        body = self._get_machine_events_body(serial_number, from_dt, to_dt, event_type)
        return self._fetch_events(body, limit, cursor)

    def get_aggregated_machine_event_counts(self, serial_number, from_dt, to_dt=None):
        body = self._get_machine_events_body(serial_number, from_dt, to_dt)
        return self._get_aggregated_event_counts(body)

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
                                'field': 'inventory.source.name',
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
        r = self._client.search(index=self.read_index, body=body)
        heartbeats = []
        for bucket in r["aggregations"]["inventory_heartbeats"]["sources"]["buckets"]:
            heartbeats.append((event_types["inventory_heartbeat"],
                               bucket["key"],
                               [(None, parser.parse(bucket["max_created_at"]["value_as_string"], ignoretz=True))]))
        for bucket in r["aggregations"]["other_events"]["event_types"]["buckets"]:
            event_type = bucket["key"]
            event_type_class = event_types.get(event_type, None)
            if not event_type_class:
                logger.error("Unknown event type %s", event_type)
            else:
                ua_list = []
                for sub_bucket in bucket["user_agents"]["buckets"]:
                    ua = sub_bucket["key"]
                    ua_list.append((ua, parser.parse(sub_bucket["max_created_at"]["value_as_string"], ignoretz=True)))
                heartbeats.append((event_type_class, None, ua_list))
        return heartbeats

    def get_machine_events_url(self, serial_number, from_dt, to_dt=None, event_type=None):
        return self._build_kibana_url(
            self._get_machine_events_body(serial_number, event_type=event_type),
            from_dt, to_dt
        )

    # object events

    def _get_object_events_body(self, key, val, from_dt=None, to_dt=None, event_type=None):
        self.wait_and_configure_if_necessary()
        filters = [
            {'term': {f'objects.{key}': val}},
        ]
        range_kwargs = {}
        if from_dt:
            range_kwargs["gte"] = from_dt
        if to_dt:
            range_kwargs["lt"] = to_dt
        if range_kwargs:
            filters.append({'range': {'created_at': range_kwargs}})
        if event_type:
            filters.append(self._get_type_filter(event_type))
        return {'query': {'bool': {'filter': filters}}}

    def fetch_object_events(self, key, val, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        body = self._get_object_events_body(key, val, from_dt, to_dt, event_type)
        return self._fetch_events(body, limit, cursor)

    def get_aggregated_object_event_counts(self, key, val, from_dt, to_dt=None):
        body = self._get_object_events_body(key, val, from_dt, to_dt)
        return self._get_aggregated_event_counts(body)

    def get_object_events_url(self, key, val, from_dt, to_dt=None, event_type=None):
        return self._build_kibana_url(
            self._get_object_events_body(key, val, event_type=event_type),
            from_dt, to_dt
        )

    # probe events

    def _get_probe_events_body(self, probe, from_dt=None, to_dt=None, event_type=None):
        self.wait_and_configure_if_necessary()
        filters = [
            {'term': {'probes.pk': probe.pk}},
        ]
        range_kwargs = {}
        if from_dt:
            range_kwargs["gte"] = from_dt
        if to_dt:
            range_kwargs["lt"] = to_dt
        if range_kwargs:
            filters.append({'range': {'created_at': range_kwargs}})
        if event_type:
            filters.append(self._get_type_filter(event_type))
        return {'query': {'bool': {'filter': filters}}}

    def fetch_probe_events(self, probe, from_dt, to_dt=None, event_type=None, limit=10, cursor=None):
        body = self._get_probe_events_body(probe, from_dt, to_dt, event_type)
        return self._fetch_events(body, limit, cursor)

    def get_aggregated_probe_event_counts(self, probe, from_dt, to_dt=None):
        body = self._get_probe_events_body(probe, from_dt, to_dt)
        return self._get_aggregated_event_counts(body)

    def get_probe_events_url(self, probe, from_dt, to_dt=None, event_type=None):
        return self._build_kibana_url(
            self._get_probe_events_body(probe, event_type=event_type),
            from_dt, to_dt
        )

    # zentral apps data

    def _get_hist_query_dict(self, interval, bucket_number, tag):
        unit = self.INTERVAL_UNIT[interval]
        gte_range = f"now-{bucket_number - 1}{unit}/{unit}"
        lt_range = f"now+1{unit}/{unit}"
        return {
            "bool": {
                "filter": [
                    {"term": {"tags": tag}},
                    {"range": {"created_at": {"gte": gte_range, "lt": lt_range}}}
                ]
            }
        }

    def _get_hist_date_histogram_dict(self, interval, bucket_number, field="created_at"):
        unit = self.INTERVAL_UNIT[interval]
        min_bound = f"now-{bucket_number - 1}{unit}/{unit}"
        max_bound = f"now/{unit}"
        if self.version >= [7, 2]:
            interval_attr = "calendar_interval"
        else:
            interval_attr = "interval"
        return {
            "field": field,
            interval_attr: interval,
            "min_doc_count": 0,
            "extended_bounds": {
                "min": min_bound,
                "max": max_bound
            }
        }

    def get_app_hist_data(self, interval, bucket_number, tag):
        self.wait_and_configure_if_necessary()
        body = {"query": self._get_hist_query_dict(interval, bucket_number, tag),
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
        r = self._client.search(index=self.read_index, body=body)
        return [(parser.parse(b["key_as_string"], ignoretz=True), b["doc_count"], b["unique_msn"]["value"])
                for b in r['aggregations']['buckets']['buckets']]

    def close(self):
        self._client.close()


# Serializers


class IndexSerializer(EventFilterSetSerializer):
    name = serializers.CharField(allow_blank=False)
    priority = serializers.IntegerField(min_value=1)


class ESOSStoreSerializer(serializers.Serializer):
    hosts = serializers.ListField(
        child=HTTPURLField(),
        min_length=1,
    )
    verify_certs = serializers.BooleanField(required=False, default=True)
    ssl_show_warn = serializers.BooleanField(required=False, default=True)
    username = serializers.CharField(required=False, allow_null=True)
    password = serializers.CharField(required=False, allow_null=True)
    batch_size = serializers.IntegerField(
        default=1,
        min_value=1,
        max_value=ESOSStore.max_batch_size
    )
    # indices
    index = serializers.CharField(required=False)
    indices = IndexSerializer(many=True, required=False)
    read_index = serializers.CharField(required=False)
    number_of_shards = serializers.IntegerField(min_value=1, default=1, required=False)
    number_of_replicas = serializers.IntegerField(min_value=0, default=0, required=False)
    # kibana
    kibana_discover_url = serializers.CharField(required=False)
    kibana_index_pattern_uuid = serializers.CharField(required=False)

    def validate(self, data):
        # username and password for basic auth
        username = data.get("username")
        password = data.get("password")
        if username and not password:
            raise serializers.ValidationError({"password": "Required when username is set"})
        elif password and not username:
            raise serializers.ValidationError({"username": "Required when password is set"})

        # indices
        indices = data.get("indices")
        if data.get("index"):
            if indices:
                raise serializers.ValidationError({"index": "Cannot be set when multiple indices are configured"})
        else:
            if not indices:
                raise serializers.ValidationError({"indices": "Required when index is empty"})
            if len(set(idx["priority"] for idx in indices)) < len(indices):
                raise serializers.ValidationError({"indices": "All indices must have a different priority"})
            if len(set(idx["name"] for idx in indices)) < len(indices):
                raise serializers.ValidationError({"indices": "All indices must have a different name"})
            default_index = sorted(indices, key=lambda idx: idx["priority"])[0]
            if EventFilterSet.from_mapping(default_index):
                raise serializers.ValidationError(
                    {"indices": f"Default index {default_index['name']} (lowest priority) cannot be filtered"}
                )
            if not data.get("read_index"):
                raise serializers.ValidationError({"read_index": "Required when multiple indices are configured"})

        return data
