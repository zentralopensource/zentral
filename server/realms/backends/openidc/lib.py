import base64
import hashlib
import json
import random
import time
from urllib.parse import urlencode
from django.core.exceptions import SuspiciousOperation
import requests
from josepy.jwk import JWK
from josepy.jws import JWS, Header


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


def verify_jws(token, client_id, openid_configuration):
    jws = JWS.from_compact(token.encode("ascii"))
    json_header = jws.signature.protected
    header = Header.json_loads(json_header)

    # alg
    alg = jws.signature.combined.alg.name.upper()
    if "NONE" in alg:
        raise SuspiciousOperation("ID token is not signed")
    if alg not in (alg.upper() for alg in openid_configuration["id_token_signing_alg_values_supported"]):
        raise SuspiciousOperation("Unexpected ID token signature algorithm")

    # retrieve signature key
    # TODO cache
    jwks_response = requests.get(openid_configuration["jwks_uri"], headers={"Accept": "application/json"})
    jwks_response.raise_for_status()
    jwk = None
    for jwk_json in jwks_response.json()["keys"]:
        if jwk_json["kid"] == header.kid:
            jwk = JWK.from_json(jwk_json)
            break
    if not jwk:
        raise SuspiciousOperation("Could not find ID token signing key")

    # verify signature
    if not jws.verify(jwk):
        raise SuspiciousOperation("Invalid ID token signature")

    payload = json.loads(jws.payload.decode('utf-8'))

    # iss
    if payload.get("iss") != openid_configuration["issuer"]:
        raise SuspiciousOperation("Invalid ID token 'iss'")

    # aud
    if payload.get("aud") != client_id:
        raise SuspiciousOperation("Invalid ID token 'aud'")

    timestamp = int(time.time())

    # nbf
    nbf = payload.get("nbf")
    if nbf is not None:
        try:
            nbf = int(nbf)
        except (TypeError, ValueError):
            raise SuspiciousOperation("Invalid ID token 'nbf'")
        if timestamp < nbf - TIMESTAMP_LEEWAY:
            raise SuspiciousOperation("ID token not valid yet")

    # exp
    exp = payload.get("exp")
    if exp is not None:
        try:
            exp = int(exp)
        except (TypeError, ValueError):
            raise SuspiciousOperation("Invalid ID token 'exp'")
        if timestamp > exp + TIMESTAMP_LEEWAY:
            raise SuspiciousOperation("ID token has expired")

    return payload


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
