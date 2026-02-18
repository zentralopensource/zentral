import logging
import base64
import hashlib
import random
from urllib.parse import urlencode
from django.core.exceptions import SuspiciousOperation
import requests

from jwt import PyJWKClient
import jwt

logger = logging.getLogger("server.realms.backends.openidc.lib")

try:
    random = random.SystemRandom()
except NotImplementedError:
    print('No secure pseudo random number generator available.')


TIMESTAMP_LEEWAY = 60


# PKCE


def _b64encode_for_pkce(bytes_like):
    return base64.urlsafe_b64encode(bytes_like).decode("ascii").rstrip("=")


def _generate_code_verifier():
    b = bytearray(random.getrandbits(8) for i in range(32))
    return _b64encode_for_pkce(b)


def _compute_code_challenge(code_verifier):
    h = hashlib.sha256(code_verifier.encode("ascii"))
    return _b64encode_for_pkce(h.digest())


def generate_pkce_codes():
    code_verifier = _generate_code_verifier()
    code_challenge = _compute_code_challenge(code_verifier)
    return code_challenge, code_verifier


def _get_openid_configuration(discovery_url):
    response = requests.get(discovery_url)
    return response.json()


def build_authorization_code_flow_url(discovery_url, client_id, redirect_uri, extra_scopes, state, code_challenge):
    scopes = ["openid"]
    if extra_scopes:
        scopes.extend(extra_scopes)

    data = {"client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": state,
            }
    if code_challenge:
        # PKCE
        data["code_challenge_method"] = "S256",
        data["code_challenge"] = code_challenge

    openid_configuration = _get_openid_configuration(discovery_url)
    return "{}?{}".format(openid_configuration["authorization_endpoint"], urlencode(data))


def verify_jws(token, audience, openid_configuration):
    issuer = openid_configuration["issuer"]
    try:
        return _verify_jws(
            token=token,
            audience=audience,
            issuer=issuer,
            oid_config=openid_configuration)
    except jwt.ExpiredSignatureError:
        raise SuspiciousOperation("ID token has expired")
    except jwt.ImmatureSignatureError:
        raise SuspiciousOperation("ID token not valid yet")
    except jwt.InvalidIssuerError:
        raise SuspiciousOperation("Invalid ID token 'iss'")
    except jwt.InvalidAudienceError:
        raise SuspiciousOperation("Invalid ID token 'aud'")
    except jwt.MissingRequiredClaimError as e:
        if e.claim == "iss":
            raise SuspiciousOperation("Invalid ID token 'iss'")
        if e.claim == "aud":
            raise SuspiciousOperation("Invalid ID token 'aud'")
        raise SuspiciousOperation("Invalid ID token signature")
    except jwt.InvalidAlgorithmError:
        raise SuspiciousOperation("Unexpected ID token signature algorithm")
    except (jwt.InvalidSignatureError, jwt.DecodeError, jwt.PyJWTError):
        raise SuspiciousOperation("Invalid ID token signature")


def verify_jws_with_discovery(token: str, audience: str, issuer_uri: str) -> dict:
    oid_config = _get_openid_configuration(issuer_uri.rstrip("/") + "/.well-known/openid-configuration")

    return _verify_jws(
        token=token,
        audience=audience,
        issuer=issuer_uri,
        oid_config=oid_config
    )


def _verify_jws(token: str, audience: str, issuer: str, oid_config: dict):
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if algorithm and "NONE" == algorithm.upper():
        raise SuspiciousOperation("ID token is not signed")
    supported_algorithms = [a for a in oid_config["id_token_signing_alg_values_supported"] if a.upper() != "NONE"]

    try:
        jwk_client = PyJWKClient(oid_config["jwks_uri"])
        signing_key = jwk_client.get_signing_key_from_jwt(token).key
    except Exception:
        msg = "Could not find ID token signing key"
        logger.exception(msg)
        raise SuspiciousOperation(msg)

    return jwt.decode(
        token,
        key=signing_key,
        algorithms=supported_algorithms,
        audience=audience,
        issuer=issuer,
        leeway=TIMESTAMP_LEEWAY,
        options={
            "require": ["iss", "aud"],
        },
    )


def get_claims(discovery_url, client_id, redirect_uri, authorization_code, client_secret, code_verifier):
    openid_configuration = _get_openid_configuration(discovery_url)

    # use authorization code to get the tokens
    data = {"client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code": authorization_code,
            }
    if client_secret:
        data["client_secret"] = client_secret
    else:
        # PKCE
        data["code_verifier"] = code_verifier
    response = requests.post(openid_configuration["token_endpoint"], data=data)
    response.raise_for_status()
    response_j = response.json()

    # decode & verify claims
    claims = verify_jws(response_j["id_token"], client_id, openid_configuration)

    # enrich claims with userinfo endpoint if possible
    userinfo_endpoint = openid_configuration.get("userinfo_endpoint")
    access_token = response_j.get("access_token")
    if userinfo_endpoint and access_token:
        userinfo_response = requests.get(userinfo_endpoint,
                                         headers={"Accept": "application/json",
                                                  "Authorization": "Bearer {}".format(access_token)})
        if userinfo_response.ok:
            claims.update(userinfo_response.json())

    return claims
