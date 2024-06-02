import os
import boto3
import requests


def get_region():
    region = os.environ.get("AWS_REGION")
    if not region:
        metadata_service_url = "http://169.254.169.254/latest/"
        r = requests.put(
            metadata_service_url + "api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "10"},
            timeout=.5
        )
        r.raise_for_status()
        token = r.text.strip()
        r = requests.get(
            metadata_service_url + "dynamic/instance-identity/document",
            headers={"X-aws-ec2-metadata-token": token}
        )
        r.raise_for_status()
        data = r.json()
        region = data["region"]
    return region


def make_get_caller_identity_request():
    sts_client = boto3.client("sts")
    event_system = sts_client.meta.events
    iam_request = {}

    def inspect_request_before_send(request, **kwargs):
        iam_request["method"] = request.method
        iam_request["url"] = request.url
        iam_request["headers"] = {k: v.decode("utf-8") if isinstance(v, bytes) else v
                                  for k, v in request.headers.items()}
        iam_request["body"] = request.body

    event_system.register('before-send.sts.GetCallerIdentity', inspect_request_before_send)
    # TODO: find a way to not have to make the call to get the information
    # by returning an AWSResponse object in inspect_request_before_send.
    sts_client.get_caller_identity()
    return iam_request
