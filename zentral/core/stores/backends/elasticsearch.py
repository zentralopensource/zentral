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

    @classmethod
    def _get_client_kwargs(cls, config_d):
        kwargs = super()._get_client_kwargs(config_d)
        basic_auth = config_d.get("basic_auth")
        if basic_auth:
            kwargs["basic_auth"] = basic_auth
        return kwargs

    def _streaming_bulk(self, *args, **kwargs):
        return streaming_bulk(*args, **kwargs)
