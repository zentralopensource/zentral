import base64
from importlib import import_module
from django.utils.functional import SimpleLazyObject
import requests
from base.utils import deployment_info
from zentral.conf import settings
from zentral.utils.aws import make_get_caller_identity_request


class ZentralSaaSPushCSRSigner:
    def __init__(self, config_d):
        self.url = config_d["url"]

    def get_signed_b64_csr(self, csr):
        payload = {
            "b64_csr": base64.b64encode(csr).decode("ascii"),
            "fqdn": settings["api"]["fqdn"],
            "iam_request": make_get_caller_identity_request(),
        }
        resp = requests.post(
            self.url, json=payload,
            headers={"User-Agent": deployment_info.user_agent},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()["signed_csr"].encode("ascii")


def get_signer():
    config = settings["apps"]["zentral.contrib.mdm"].get("push_csr_signer")
    if not config:
        return
    backend = config.get("backend")
    module_path, class_name = backend.rsplit(".", 1)
    module = import_module(module_path)
    signer_class = getattr(module, class_name)
    return signer_class(config)


signer = SimpleLazyObject(get_signer)
