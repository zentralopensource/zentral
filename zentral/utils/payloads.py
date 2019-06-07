import logging
import subprocess
from urllib.parse import urlparse
import uuid
from zentral.conf import settings


logger = logging.getLogger("zentral.utils.payloads")


def generate_payload_uuid():
    return str(uuid.uuid4())


def get_payload_identifier(suffix):
    o = urlparse(settings["api"]["tls_hostname"])
    netloc = o.netloc.split(":")[0].split(".")
    netloc.reverse()
    netloc.append(suffix)
    return ".".join(netloc)


def sign_payload_openssl(payload):
    api_settings = settings["api"]
    p = subprocess.Popen(["/usr/bin/openssl", "smime", "-sign",
                          "-signer", api_settings["tls_server_certs"],
                          "-inkey", api_settings["tls_server_key"],
                          "-certfile",  api_settings["tls_server_certs"],
                          "-outform", "der", "-nodetach"],
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    stdout, stderr = p.communicate(payload)
    if not stdout:
        logger.error("Could not sign payload: %s", stderr.decode("utf-8", errors="replace"))
        return payload
    else:
        return stdout
