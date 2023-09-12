import logging
from zentral.utils.aws import get_region as get_aws_region


logger = logging.getLogger("zentral.conf.secrets")


class AWSSecretClient:
    platform = "AWS"
    metadata_service_url = "http://169.254.169.254/latest/"

    def __init__(self):
        import boto3
        # fail early if no authentication
        sts = boto3.client("sts")
        sts.get_caller_identity()
        self._client = boto3.client('secretsmanager', region_name=get_aws_region())

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
