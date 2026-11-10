import logging
import base64
import hashlib
import hmac
import random
import secrets
from urllib.parse import urlencode

from django.core.exceptions import SuspiciousOperation
import requests

from realms.exceptions import RealmUserError
from zentral.utils.oidc import get_openid_configuration, uses_https, verify_jws
from zentral.utils.requests import make_session


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


def generate_nonce():
    return secrets.token_urlsafe(32)


def build_authorization_code_flow_url(discovery_url, client_id, redirect_uri, extra_scopes, state, code_challenge,
                                      nonce):
    scopes = ["openid"]
    if extra_scopes:
        scopes.extend(extra_scopes)

    data = {"client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(scopes),
            "state": state,
            "nonce": nonce,
            }
    if code_challenge:
        # PKCE
        data["code_challenge_method"] = "S256"
        data["code_challenge"] = code_challenge

    openid_configuration = get_openid_configuration(discovery_url)
    return "{}?{}".format(openid_configuration["authorization_endpoint"], urlencode(data))


def get_userinfo_claims(response, id_token_sub):
    # a signed or encrypted response is a JWT, and not JSON
    try:
        userinfo = response.json()
    except ValueError:
        logger.warning("UserInfo response skipped: it is not JSON")
        return {}
    if not isinstance(userinfo, dict):
        logger.warning("UserInfo response skipped: it is not a JSON object")
        return {}
    # OpenID Connect Core 1.0 §5.3.2
    if id_token_sub is None:
        logger.warning("UserInfo response skipped: the ID token has no sub")
        return {}
    if userinfo.get("sub") != id_token_sub:
        logger.warning("UserInfo response skipped: its sub is not the sub of the ID token")
        return {}
    return userinfo


def get_claims(discovery_url, client_id, redirect_uri, authorization_code, client_secret, code_verifier, nonce):
    # a RealmUserError gives the error page of the authentication session
    try:
        openid_configuration = get_openid_configuration(discovery_url)
    except (requests.RequestException, ValueError):
        raise RealmUserError("Could not get the OpenID configuration")

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
    # the token request carries the authorization code and the client secret,
    # and the userinfo request the access token
    token_endpoint = openid_configuration.get("token_endpoint")
    if not uses_https(token_endpoint):
        raise SuspiciousOperation("The token endpoint does not use https")
    userinfo_endpoint = openid_configuration.get("userinfo_endpoint")
    if userinfo_endpoint and not uses_https(userinfo_endpoint):
        raise SuspiciousOperation("The userinfo endpoint does not use https")
    with make_session() as session:
        try:
            response = session.post(token_endpoint, data=data, allow_redirects=False)
        except requests.RequestException:
            raise RealmUserError("Could not get the tokens")
        if response.status_code != 200:
            raise SuspiciousOperation(f"Token endpoint response status {response.status_code}")
        try:
            response_j = response.json()
        except ValueError:
            response_j = None
        if not isinstance(response_j, dict) or not isinstance(response_j.get("id_token"), str):
            raise SuspiciousOperation("Invalid token response")

        # decode & verify claims
        claims = verify_jws(
            token=response_j["id_token"],
            issuer=openid_configuration["issuer"],
            audience=client_id,
            openid_configuration=openid_configuration,
            exception_class=SuspiciousOperation,
        )

        # OpenID Connect Core 1.0 §3.1.3.7, step 11. A session started before the nonce was sent has none.
        id_token_nonce = claims.get("nonce")
        if (
            not nonce
            or not isinstance(id_token_nonce, str)
            # compare_digest refuses a str that is not ASCII, and JSON can carry a lone surrogate
            or not hmac.compare_digest(id_token_nonce.encode("utf-8", "surrogatepass"), nonce.encode("utf-8"))
        ):
            raise SuspiciousOperation("Invalid nonce")

        # enrich claims with userinfo endpoint if possible
        access_token = response_j.get("access_token")
        if userinfo_endpoint and access_token:
            try:
                userinfo_response = session.get(userinfo_endpoint,
                                                headers={"Accept": "application/json",
                                                         "Authorization": "Bearer {}".format(access_token)},
                                                allow_redirects=False)
            except requests.RequestException:
                logger.warning("UserInfo request error", exc_info=True)
            else:
                if userinfo_response.status_code == 200:
                    claims.update(get_userinfo_claims(userinfo_response, claims.get("sub")))

    return claims
