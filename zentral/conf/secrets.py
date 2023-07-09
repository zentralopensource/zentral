import logging
import os
import requests


logger = logging.getLogger("zentral.conf.secrets")


class AWSSecretClient:
    platform = "AWS"
    metadata_service_url = "http://169.254.169.254/latest/"

    def __init__(self):
        import boto3
        sts = boto3.client("sts")
        # fail early if no authentication
        sts.get_caller_identity()
        # get region
        region = os.environ.get("AWS_REGION")
        if not region:
            r = requests.put(
                self.metadata_service_url + "api/token",
                headers={"X-aws-ec2-metadata-token-ttl-seconds": "10"},
                timeout=.5
            )
            r.raise_for_status()
            token = r.text.strip()
            r = requests.get(
                self.metadata_service_url + "dynamic/instance-identity/document",
                headers={"X-aws-ec2-metadata-token": token}
            )
            r.raise_for_status()
            data = r.json()
            region = data["region"]
        # setup secrets manager client
        self._client = boto3.client('secretsmanager', region_name=region)

    def get(self, name):
        logger.debug("Get AWS secret %s", name)
        return self._client.get_secret_value(SecretId=name)["SecretString"]


class GCPSecretClient:
    platform = "GCP"

    def __init__(self):
        import google.auth
        from google.cloud import secretmanager as sm
        _, project = google.auth.default()
        if project:
            self._client = sm.SecretManagerServiceClient()
            self._project = project
        else:
            raise RuntimeError("Could not get default GCP project")

    def get(self, name):
        logger.debug("Get GCP secret %s", name)
        path = "{}/versions/{}".format(self._client.secret_path(self._project, name), "latest")
        return self._client.access_secret_version(request={"name": path}).payload.data.decode("UTF-8")


def get_secret_client():
    for client_class in (AWSSecretClient, GCPSecretClient):
        try:
            client = client_class()
        except Exception as e:
            logger.debug("Cloud not instantiate %s secret client: %s",
                         client_class.platform, e)
        else:
            logger.debug("%s secret client instantiated", client.platform)
            return client
    raise RuntimeError("Could not instantiate secret client")
