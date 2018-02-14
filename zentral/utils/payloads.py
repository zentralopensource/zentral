from urllib.parse import urlparse
import uuid
from zentral.conf import settings


def generate_payload_uuid():
    return str(uuid.uuid4())


def get_payload_identifier(suffix):
    o = urlparse(settings["api"]["tls_hostname"])
    netloc = o.netloc.split(":")[0].split(".")
    netloc.reverse()
    netloc.append(suffix)
    return ".".join(netloc)
