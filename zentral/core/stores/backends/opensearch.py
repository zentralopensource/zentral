import logging
import boto3
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection
from opensearchpy.helpers import streaming_bulk
from opensearchpy.exceptions import ConnectionError, RequestError
from zentral.core.exceptions import ImproperlyConfigured
from .es_os_base import ESOSEventStore


logger = logging.getLogger('zentral.core.stores.backends.opensearch')


class EventStore(ESOSEventStore):
    client_class = OpenSearch
    connection_error_class = ConnectionError
    request_error_class = RequestError

    def _get_client_kwargs(self, config_d):
        kwargs = super()._get_client_kwargs(config_d)
        aws_auth = config_d.get("aws_auth")
        if aws_auth is None:
            logger.info("No AWS authentication")
            return kwargs
        try:
            region = aws_auth["region"]
        except KeyError:
            raise ImproperlyConfigured("Missing region in aws_auth")
        try:
            access_key_id, secret_access_key = aws_auth["access_key_id"], aws_auth["secret_access_key"]
        except KeyError:
            credentials = boto3.Session().get_credentials()
        else:
            credentials = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            ).get_credentials()
        if not credentials:
            raise ImproperlyConfigured("Could not get AWS credentials")
        kwargs["http_auth"] = AWSV4SignerAuth(credentials, region)
        kwargs["connection_class"] = RequestsHttpConnection
        logger.info("AWS authentication configured")
        return kwargs

    def _streaming_bulk(self, *args, **kwargs):
        return streaming_bulk(*args, **kwargs)
