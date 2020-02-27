import base64
import hashlib
import random
import requests
from urllib.parse import urlencode, urljoin
import jwt


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


def _get_openid_connect_urls(discovery_url):
    response = requests.get(discovery_url)
    response_j = response.json()
    return [urljoin(discovery_url, response_j.get(attr))
            for attr in ("authorization_endpoint", "token_endpoint")]


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

    authorization_url, _ = _get_openid_connect_urls(discovery_url)
    return "{}?{}".format(authorization_url, urlencode(data))


def get_id_token(discovery_url, client_id, redirect_uri, authorization_code, client_secret, code_verifier):
    data = {"client_id": client_id,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "code": authorization_code,
            }
    if client_id:
        data["client_secret"] = client_secret
    else:
        # PKCE
        data["code_verifier"] = code_verifier

    _, token_url = _get_openid_connect_urls(discovery_url)
    response = requests.post(token_url, data=data)
    response.raise_for_status()
    response_j = response.json()
    raw_id_token = response_j["id_token"]
    # TODO: verification !!!
    return jwt.decode(raw_id_token, verify=False)
