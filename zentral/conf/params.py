import logging
import requests


logger = logging.getLogger("zentral.conf.params")


class AWSSSMClient:
    platform = "AWS"

    def __init__(self):
        import boto3
        sts = boto3.client("sts")
        sts.get_caller_identity()
        self._client = boto3.client('ssm')

    def get(self, key):
        return self._client.get_parameter(Name=key)["Parameter"]["Value"]


class GCPMetadataClient:
    platform = "GCP"
    metadata_base_url = "http://metadata.google.internal/computeMetadata/v1/"

    def __init__(self):
        import google.auth
        google.auth.default()
        self._make_request()

    def _make_request(self, rel_path=None):
        r = requests.get(
            "{}{}".format(self.metadata_base_url, rel_path or ""),
            headers={"Metadata-Flavor": "Google"},
            timeout=.5,
        )
        r.raise_for_status()
        return r

    def get(self, key):
        key = key.strip("./~")
        r = self._make_request("project/attributes/{}".format(key))
        return r.text


def get_param_client():
    for client_class in (AWSSSMClient, GCPMetadataClient):
        try:
            client = client_class()
        except Exception as e:
            logger.info("Could not instantiate %s param client: %s",
                        client_class.platform, e)
        else:
            logger.info("%s param client instantiated", client.platform)
            return client
    raise RuntimeError("Cloud not instantiate param client")
