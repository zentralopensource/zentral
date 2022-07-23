import logging
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk
from elasticsearch.exceptions import ConnectionError, RequestError
from .es_os_base import ESOSEventStore


logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')


class EventStore(ESOSEventStore):
    client_class = Elasticsearch
    streaming_bulk = streaming_bulk
    connection_error_class = ConnectionError
    request_error_class = RequestError
