import logging
import os
import subprocess
import tempfile
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
    old_umask = os.umask(0o077)
    fcfd, fullchain = tempfile.mkstemp(suffix="-tls_fullchain.pem")
    with os.fdopen(fcfd, "w") as fcf:
        fcf.write(api_settings["tls_fullchain"])
    pkfd, privkey = tempfile.mkstemp(suffix="-tls_privkey.pem")
    with os.fdopen(pkfd, "w") as pkf:
        pkf.write(api_settings["tls_privkey"])
    p = subprocess.Popen(["/usr/bin/openssl", "smime", "-sign",
                          "-signer", fullchain, "-certfile",  fullchain,
                          "-inkey", privkey,
                          "-outform", "der", "-nodetach"],
                         stderr=subprocess.PIPE,
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    stdout, stderr = p.communicate(payload)
    os.unlink(fullchain)
    os.unlink(privkey)
    os.umask(old_umask)
    if not stdout:
        logger.error("Could not sign payload: %s", stderr.decode("utf-8", errors="replace"))
        return payload
    else:
        return stdout
