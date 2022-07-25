import logging
from elasticsearch import Elasticsearch
from elasticsearch.helpers import streaming_bulk
from elasticsearch.exceptions import ConnectionError, RequestError
from .es_os_base import ESOSEventStore


logger = logging.getLogger('zentral.core.stores.backends.elasticsearch')


class EventStore(ESOSEventStore):
    client_class = Elasticsearch
    connection_error_class = ConnectionError
    request_error_class = RequestError

    def _streaming_bulk(self, *args, **kwargs):
        return streaming_bulk(*args, **kwargs)
