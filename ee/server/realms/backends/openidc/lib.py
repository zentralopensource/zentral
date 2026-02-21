import logging
import base64
import hashlib
import random
from urllib.parse import urlencode

from django.core.exceptions import SuspiciousOperation
import requests

from zentral.utils.oidc import get_openid_configuration, verify_jws


logger = logging.getLogger("server.realms.backends.openidc.lib")

try:
    random = random.SystemRandom()
except NotImplementedError:
    print('No secure pseudo random number generator available.')


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

    openid_configuration = get_openid_configuration(discovery_url)
    return "{}?{}".format(openid_configuration["authorization_endpoint"], urlencode(data))


def get_claims(discovery_url, client_id, redirect_uri, authorization_code, client_secret, code_verifier):
    openid_configuration = get_openid_configuration(discovery_url)

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
    claims = verify_jws(
        token=response_j["id_token"],
        issuer=openid_configuration["issuer"],
        audience=client_id,
        openid_configuration=openid_configuration,
        exception_class=SuspiciousOperation,
    )

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
