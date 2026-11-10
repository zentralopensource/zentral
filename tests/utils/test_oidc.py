import base64
import hashlib
import hmac
import json
import time
from unittest.mock import patch
from urllib.error import HTTPError

import jwt
import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm
from django.test import TestCase
from django.utils.crypto import get_random_string
import responses

from base.utils import deployment_info
from zentral.utils.oidc import get_openid_configuration, verify_jws, verify_jws_with_discovery


# see https://github.com/jpadilla/pyjwt/blob/2.15.0/jwt/jwks_client.py#L167
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
        cls.public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk_json = RSAAlgorithm.to_jwk(public_key)
        jwk = json.loads(jwk_json)
        jwk["kid"] = "test-kid"
        jwk["use"] = "sig"
        jwk["alg"] = "RS256"
        jwks_dict = {"keys": [jwk]}
        cls.jwks_payload = json.dumps(jwks_dict).encode("utf-8")

    # utils

    @staticmethod
    def _make_oid_config(issuer, algorithms=None):
        return {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/jwks",
            "id_token_signing_alg_values_supported": algorithms or ["RS256"],
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

    # jwt.encode refuses the public key as an HMAC secret, so the forged token is assembled here
    def _make_hs256_token_signed_with_the_public_key(self, iss, aud, kid="test-kid"):
        now = int(time.time())
        segments = [
            self._b64encode({"alg": "HS256", "typ": "JWT", "kid": kid}),
            self._b64encode({"iss": iss, "aud": aud, "sub": "user-123", "iat": now, "exp": now + 300}),
        ]
        signing_input = b".".join(segments)
        segments.append(
            base64.urlsafe_b64encode(hmac.new(self.public_pem, signing_input, hashlib.sha256).digest()).rstrip(b"=")
        )
        return b".".join(segments).decode("utf-8")

    @staticmethod
    def _b64encode(payload):
        return base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).rstrip(b"=")

    # test get_openid_configuration

    def test_get_openid_configuration_missing_issuer(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.get("https://issuer.zentral.com", json={})
            with self.assertRaisesRegex(
                ValueError,
                r"Missing 'id_token_signing_alg_values_supported' in OpenID configuration"
            ):
                get_openid_configuration("https://issuer.zentral.com")

    def test_get_openid_configuration_wrong_attr_type(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.get("https://issuer.zentral.com", json={
                "id_token_signing_alg_values_supported": ["RS256"],
                "issuer": "https://issuer.zentral.com",
                "jwks_uri": None,  # Not a string
            })
            with self.assertRaisesRegex(
                ValueError,
                r"OpenID configuration 'jwks_uri' is not a str"
            ):
                get_openid_configuration("https://issuer.zentral.com")

    def test_get_openid_configuration(self):
        cfg = self._make_oid_config("https://issuer.zentral.com")
        discovery_uri = "https://issuer.zentral.com/.well-known/openid-configuration"
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.get(discovery_uri, json=cfg)
            self.assertEqual(get_openid_configuration(discovery_uri), cfg)
            self.assertEqual(len(rsps.calls), 1)
            self.assertEqual(rsps.calls[0].request.url, discovery_uri)
            self.assertEqual(rsps.calls[0].request.headers["User-Agent"], deployment_info.user_agent)
            self.assertEqual(rsps.calls[0].request.req_kwargs["timeout"], 10)

    def test_get_openid_configuration_redirect(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            # the target is not registered: following the redirect would raise a ConnectionError
            rsps.get("https://issuer.zentral.com", status=302,
                     headers={"Location": "http://169.254.169.254/latest/meta-data/"})
            with self.assertRaisesRegex(ValueError, r"OpenID configuration response status 302"):
                get_openid_configuration("https://issuer.zentral.com")
            self.assertEqual(len(rsps.calls), 1)

    def test_get_openid_configuration_not_a_json_object(self):
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            rsps.get("https://issuer.zentral.com", json=["issuer"])
            with self.assertRaisesRegex(ValueError, r"OpenID configuration is not a JSON object"):
                get_openid_configuration("https://issuer.zentral.com")

    def test_get_openid_configuration_jwks_uri_not_https(self):
        for jwks_uri in ("file:///etc/passwd", "http://169.254.169.254/latest/meta-data/", "HTTPS://issuer"):
            cfg = self._make_oid_config("https://issuer.zentral.com")
            cfg["jwks_uri"] = jwks_uri
            with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
                rsps.get("https://issuer.zentral.com", json=cfg)
                with self.assertRaisesRegex(ValueError, r"OpenID configuration 'jwks_uri' does not use https"):
                    get_openid_configuration("https://issuer.zentral.com")

    # test verify_jws

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_success(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

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
        build_opener.return_value.open.assert_called_once()
        self.assertEqual(build_opener.return_value.open.call_args.kwargs["timeout"], 10)

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_jwks_uri_not_https(self, build_opener):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"
        token = self._make_token(iss=issuer, aud=audience)
        for jwks_uri in (None, "file:///etc/passwd", "http://169.254.169.254/latest/meta-data/"):
            openid_configuration = self._make_oid_config(issuer)
            openid_configuration["jwks_uri"] = jwks_uri
            with self.assertRaisesRegex(ValueError, r"Invalid token"):
                verify_jws(
                    token=token,
                    issuer=issuer,
                    audience=audience,
                    openid_configuration=openid_configuration,
                    exception_class=ValueError,
                )
        build_opener.assert_not_called()

    def test_verify_jws_with_discovery_errors(self):
        for error in (requests.Timeout("Boom!!!"), requests.ConnectionError("Boom!!!"), ValueError("Boom!!!")):
            with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
                rsps.get("https://issuer.zentral.com/.well-known/openid-configuration", body=error)
                with self.assertRaisesRegex(ValueError, r"^Could not get the OpenID configuration$"):
                    verify_jws_with_discovery("token", "https://issuer.zentral.com", "my-client",
                                              exception_class=ValueError)
                with self.assertRaises(type(error)):
                    verify_jws_with_discovery("token", "https://issuer.zentral.com", "my-client")

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

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_wrong_kid(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

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

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_keys_not_found(self, build_opener):
        build_opener.return_value.open.side_effect = HTTPError("Boom!", 404, "Not found", {}, None)

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

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_invalid_audience(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

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

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_expired_token(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

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

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_hmac_alg_not_supported(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_hs256_token_signed_with_the_public_key(iss=issuer, aud=audience)

        with self.assertRaisesRegex(jwt.InvalidAlgorithmError, r"The specified alg value is not allowed"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer, ["RS256", "HS256"]),
            )

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_only_hmac_algs_supported(self, build_opener):
        build_opener.return_value.open.return_value = FakeHTTPResponse(self.jwks_payload)

        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = self._make_hs256_token_signed_with_the_public_key(iss=issuer, aud=audience)

        with self.assertRaisesRegex(ValueError, r"Invalid token"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer, ["HS256"]),
                exception_class=ValueError,
            )

    @patch("jwt.jwks_client.urllib.request.build_opener")
    def test_verify_jws_deeply_nested_payload(self, build_opener):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"

        token = b".".join([
            self._b64encode({"alg": "RS256", "typ": "JWT", "kid": "test-kid"}),
            base64.urlsafe_b64encode(b"[" * 1_000_000 + b"]" * 1_000_000).rstrip(b"="),
            base64.urlsafe_b64encode(b"forged-sig").rstrip(b"="),
        ]).decode("utf-8")

        with self.assertRaisesRegex(ValueError, r"Invalid token"):
            verify_jws(
                token=token,
                issuer=issuer,
                audience=audience,
                openid_configuration=self._make_oid_config(issuer),
                exception_class=ValueError,
            )
        build_opener.assert_not_called()
