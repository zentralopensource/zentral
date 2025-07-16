import logging
import boto3
from opensearchpy import AWSV4SignerAuth, OpenSearch, RequestsHttpConnection
from opensearchpy.helpers import streaming_bulk
from opensearchpy.exceptions import ConnectionError, RequestError
from rest_framework import serializers
from .base import AWSAuthSerializer
from .es_os_base import ESOSStore, ESOSStoreSerializer


logger = logging.getLogger('zentral.core.stores.backends.opensearch')


class OpenSearchStore(ESOSStore):
    kwargs_keys = ESOSStore.kwargs_keys + (
        "aws_auth",
    )
    encrypted_kwargs_paths = ESOSStore.encrypted_kwargs_paths + (
        ["aws_auth", "aws_secret_access_key"],
    )

    client_class = OpenSearch
    connection_error_class = ConnectionError
    request_error_class = RequestError

    def _get_client_kwargs(self):
        client_kwargs = super()._get_client_kwargs()
        if not self.aws_auth:
            logger.info("No AWS authentication")
            return client_kwargs

        access_key_id = self.aws_auth.get("access_key_id")
        secret_access_key = self.aws_auth.get("secret_access_key")
        if access_key_id and secret_access_key:
            credentials = boto3.Session().get_credentials()
        else:
            credentials = boto3.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key
            ).get_credentials()
        client_kwargs["http_auth"] = AWSV4SignerAuth(credentials, self.aws_auth["region_name"])
        client_kwargs["connection_class"] = RequestsHttpConnection
        logger.info("AWS authentication configured")
        return client_kwargs

    def _streaming_bulk(self, *args, **kwargs):
        return streaming_bulk(*args, **kwargs)


# Serializers


class OpenSearchStoreSerializer(ESOSStoreSerializer):
    aws_auth = AWSAuthSerializer(required=False)

    def validate(self, data):
        data = super().validate(data)
        if data.get("username") and data.get("aws_auth"):
            raise serializers.ValidationError({"aws_auth": "Cannot be used with basic auth"})
        return data
