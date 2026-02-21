import logging

import jwt
import requests


logger = logging.getLogger("zentral.utils.oidc")


TIMESTAMP_LEEWAY = 60


def get_discovery_uri_from_issuer_uri(issuer_uri):
    return issuer_uri.rstrip("/") + "/.well-known/openid-configuration"


def get_openid_configuration(discovery_uri):
    response = requests.get(discovery_uri)
    cfg = response.json()
    for required_attr, attr_type in (
        ("id_token_signing_alg_values_supported", list),
        ("issuer", str),
        ("jwks_uri", str),
    ):
        if required_attr not in cfg:
            raise ValueError(f"Missing '{required_attr}' in OpenID configuration")
        if not isinstance(cfg[required_attr], attr_type):
            raise ValueError(f"OpenID configuration '{required_attr}' is not a {attr_type.__name__}")
    return cfg


def get_openid_configuration_from_issuer_uri(issuer_uri):
    return get_openid_configuration(get_discovery_uri_from_issuer_uri(issuer_uri))


def verify_jws(token, issuer, audience, openid_configuration, exception_class=None):
    supported_algorithms = [
        alg for alg in openid_configuration["id_token_signing_alg_values_supported"]
        if alg.upper() != "NONE"
    ]
    try:
        header = jwt.get_unverified_header(token)
        if "alg" in header and header["alg"].upper() == "NONE":
            raise jwt.InvalidAlgorithmError("The none alg is not allowed")
        jwk_client = jwt.PyJWKClient(openid_configuration["jwks_uri"])
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key=signing_key,
            algorithms=supported_algorithms,
            audience=audience,
            issuer=issuer,
            leeway=TIMESTAMP_LEEWAY,
            options={
                "require": ["iss", "aud", "exp"],
            },
        )
    except jwt.PyJWTError:
        msg = "Invalid token"
        logger.exception(msg)
        if exception_class:
            raise exception_class(msg)
        raise


def verify_jws_with_discovery(token, issuer_uri, audience, exception_class=None):
    return verify_jws(
        token, issuer_uri, audience,
        get_openid_configuration_from_issuer_uri(issuer_uri),
        exception_class,
    )
