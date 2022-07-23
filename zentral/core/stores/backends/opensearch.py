import logging
from opensearchpy import OpenSearch
from opensearchpy.helpers import streaming_bulk
from opensearchpy.exceptions import ConnectionError, RequestError
from .es_os_base import ESOSEventStore


logger = logging.getLogger('zentral.core.stores.backends.opensearch')


class EventStore(ESOSEventStore):
    client_class = OpenSearch
    streaming_bulk = streaming_bulk
    connection_error_class = ConnectionError
    request_error_class = RequestError
