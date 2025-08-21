from importlib import import_module
import logging
from django.db import models
from zentral.contrib.inventory.conf import mac_secure_enclave_from_model


logger = logging.getLogger("zentral.contrib.mdm.cert_issuer_backends")


class CertIssuerBackend(models.TextChoices):
    IDent = "IDENT", "IDent"
    MicrosoftCA = "MICROSOFT_CA", "Microsoft CA"
    OktaCA = "OKTA_CA", "Okta CA"
    StaticChallenge = "STATIC_CHALLENGE", "Static challenge"


def get_cert_issuer_backend(cert_issuer, load=False):
    backend = CertIssuerBackend(cert_issuer.backend)
    try:
        module = import_module(f"zentral.contrib.mdm.cert_issuer_backends.{backend.value.lower()}")
        backend_cls = getattr(module, backend.name)
    except (ImportError, AttributeError):
        logger.exception("Could not load cert issuer backend %s", backend)
        raise
    return backend_cls(cert_issuer, load)


cert_issuer_cache = {}


def get_cached_cert_issuer_backend(cert_issuer):
    backend = None
    version = 0
    try:
        backend, version = cert_issuer_cache[cert_issuer.pk]
    except KeyError:
        pass
    if not backend or not version or version < cert_issuer.version:
        backend = get_cert_issuer_backend(cert_issuer, load=True)
        cert_issuer_cache[cert_issuer.pk] = (backend, cert_issuer.version)
    return backend


def test_acme_payload(platform, comparable_os_version, model):
    from zentral.contrib.mdm.models import Platform
    acme = hardware_bound = attest = False
    if not platform or comparable_os_version <= (1,):
        return acme, hardware_bound, attest
    if platform == Platform.MACOS:
        if comparable_os_version >= (13, 1):
            acme = True
            secure_enclave = mac_secure_enclave_from_model(model)
            hardware_bound = secure_enclave in ("T2", "SILICON")
            attest = secure_enclave == "SILICON"
    elif platform in (Platform.IOS, Platform.IPADOS, Platform.TVOS):
        if comparable_os_version >= (16,):
            acme = hardware_bound = attest = True
    return acme, hardware_bound, attest
