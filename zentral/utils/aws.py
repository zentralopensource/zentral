import os
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
