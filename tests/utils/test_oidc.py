import json
import time
from unittest.mock import patch
from urllib.error import HTTPError

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.utils.oidc import get_openid_configuration, verify_jws


# see https://github.com/jpadilla/pyjwt/blob/b85050f1d444c6828bb4618ee764443b0a3f5d18/jwt/jwks_client.py#L108
class FakeHTTPResponse:
    def __init__(self, bytes):
        self.bytes = bytes

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return self.bytes


class OIDCUtilsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_key = private_key.public_key()
        jwk_json = RSAAlgorithm.to_jwk(public_key)
        jwk = json.loads(jwk_json)
        jwk["kid"] = "test-kid"
        jwk["use"] = "sig"
        jwk["alg"] = "RS256"
        jwks_dict = {"keys": [jwk]}
        cls.jwks_payload = json.dumps(jwks_dict).encode("utf-8")

    # utils

    @staticmethod
    def _make_oid_config(issuer):
        return {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

    def _make_token(self, iss, aud, exp=None, iat=None, sub="user-123", kid="test-kid", none_alg=False):
        now = int(time.time())
        if iat is None:
            iat = now
        if exp is None:
            exp = now + 300

        if none_alg:
            kwargs = {
                "algorithm": "none",
                "key": None,
            }
        else:
            kwargs = {
                "algorithm": "RS256",
                "headers": {"kid": kid},
                "key": self.private_pem,
            }

        return jwt.encode(
            {
                "iss": iss,
                "aud": aud,
                "sub": sub,
                "iat": iat,
                "exp": exp,
            },
            **kwargs,
        )

    # test get_openid_configuration

    @patch("zentral.utils.oidc.requests.get")
    def test_get_openid_configuration_missing_issuer(self, requests_get):
        requests_get.return_value.json.return_value = {}
        with self.assertRaisesRegex(
            ValueError,
            r"Missing 'id_token_signing_alg_values_supported' in OpenID configuration"
        ):
            get_openid_configuration("https://issuer.zentral.com")

    @patch("zentral.utils.oidc.requests.get")
    def test_get_openid_configuration_wrong_attr_type(self, requests_get):
        requests_get.return_value.json.return_value = {
            "id_token_signing_alg_values_supported": ["RS256"],
            "issuer": "https://issuer.zentral.com",
            "jwks_uri": None,  # Not a string
        }
        with self.assertRaisesRegex(
            ValueError,
            r"OpenID configuration 'jwks_uri' is not a str"
        ):
            get_openid_configuration("https://issuer.zentral.com")

    # test verify_jws

    @patch("jwt.jwks_client.urllib.request.urlopen")
    def test_verify_jws_success(self, jwt_urlopen):
        jwt_urlopen.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"
        sub = f"user_{get_random_string(5)}"

        token = self._make_token(
            iss=issuer,
            aud=audience,
            sub=sub
        )

        claims = verify_jws(
            token=token,
            issuer=issuer,
            audience=audience,
            openid_configuration=self._make_oid_config(issuer),
        )

        self.assertEqual(claims["iss"], issuer)
        self.assertEqual(claims["aud"], audience)
        self.assertEqual(claims["sub"], sub)

    def test_verify_jws_none_alg(self):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_token(
            iss=issuer,
            aud=audience,
            none_alg=True,
        )
        with self.assertRaisesRegex(jwt.PyJWTError, r"The none alg is not allowed"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
            )

    @patch("jwt.jwks_client.urllib.request.urlopen")
    def test_verify_jws_wrong_kid(self, jwt_urlopen):
        jwt_urlopen.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_token(
            iss=issuer,
            aud=audience,
            kid="not-the-expected-kid",
        )

        with self.assertRaisesRegex(
            jwt.PyJWTError,
            'Unable to find a signing key that matches: "not-the-expected-kid"'
        ):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
            )

    @patch("jwt.jwks_client.urllib.request.urlopen")
    def test_verify_jws_keys_not_found(self, jwt_urlopen):
        jwt_urlopen.side_effect = HTTPError("Boom!", 404, "Not found", {}, None)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_token(
            iss=issuer,
            aud=audience,
        )

        with self.assertRaisesRegex(
            jwt.PyJWTError,
            'Fail to fetch data from the url, err: "HTTP Error 404: Not found"'
        ):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
            )

    @patch("jwt.jwks_client.urllib.request.urlopen")
    def test_verify_jws_invalid_audience(self, jwt_urlopen):
        jwt_urlopen.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_token(
            iss=issuer,
            aud=f"{get_random_string(12)}"
        )

        with self.assertRaisesRegex(jwt.PyJWTError, r"Audience doesn't match"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
            )

    @patch("jwt.jwks_client.urllib.request.urlopen")
    def test_verify_jws_expired_token(self, jwt_urlopen):
        jwt_urlopen.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        now = int(time.time())
        token = self._make_token(
            iss=issuer,
            aud=audience, exp=now - 1000
        )

        with self.assertRaisesRegex(jwt.PyJWTError, r"Signature has expired"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
            )
