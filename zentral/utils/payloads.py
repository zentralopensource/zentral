import logging
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7
from zentral.conf import settings


logger = logging.getLogger("zentral.utils.payloads")


def generate_payload_uuid():
    return str(uuid.uuid4())


def get_payload_identifier(*suffixes):
    items = settings["api"]["fqdn"].split(".")
    items.reverse()
    for suffix in suffixes:
        if not isinstance(suffix, str):
            suffix = str(suffix)
        items.append(suffix)
    return ".".join(items)


def sign_payload(payload):
    api_settings = settings["api"]
    tls_privkey = api_settings.get("tls_privkey")
    if not tls_privkey:
        logger.error("Could not sign payload: missing tls privkey")
        return payload
    tls_fullchain = api_settings.get("tls_fullchain")
    if not tls_fullchain:
        logger.error("Could not sign payload: missing tls fullchain")
        return payload
    certificates = []
    key = serialization.load_pem_private_key(api_settings["tls_privkey"].encode("utf-8"), None)
    head = "-----BEGIN CERTIFICATE-----"
    for tail in api_settings["tls_fullchain"].split(head)[1:]:
        cert_data = (head + tail).encode("utf-8")
        certificates.append(x509.load_pem_x509_certificate(cert_data))
    signature_builder = pkcs7.PKCS7SignatureBuilder().set_data(
        payload
    ).add_signer(
        certificates.pop(0), key, hashes.SHA256()
    )
    for certificate in certificates:
        signature_builder = signature_builder.add_certificate(certificate)
    return signature_builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
