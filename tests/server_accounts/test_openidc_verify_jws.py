import io
import json
import time
from unittest.mock import patch

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from django.core.exceptions import SuspiciousOperation
from jwt.algorithms import RSAAlgorithm

from django.test import TestCase
from django.utils.crypto import get_random_string

from ee.server.realms.backends.openidc import lib  # <- ggf. anpassen


def _generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    return private_pem, public_key


class _FakeHTTPResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False


def _mock_jwks(public_key):
    jwk_json = RSAAlgorithm.to_jwk(public_key)
    jwk = json.loads(jwk_json)
    jwk["kid"] = "test-kid"
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    jwks_dict = {"keys": [jwk]}

    payload = json.dumps(jwks_dict).encode("utf-8")

    def _urlopen(_request, timeout=None, context=None):
        return _FakeHTTPResponse(payload)

    return _urlopen


def _make_token(private_pem, issuer, aud, exp=None, iat=None, sub="user-123"):
    now = int(time.time())
    if iat is None:
        iat = now
    if exp is None:
        exp = now + 300

    return jwt.encode(
        {
            "iss": issuer,
            "aud": aud,
            "sub": sub,
            "iat": iat,
            "exp": exp,
        },
        key=private_pem,
        algorithm="RS256",
        headers={"kid": "test-kid"},
    )


def _oid_config(issuer):
    return {
        "issuer": issuer,
        "jwks_uri": f"{issuer}/jwks",
        "id_token_signing_alg_values_supported": ["RS256"],
    }


class VerifyJWSTestCase(TestCase):
    def test_verify_jws_success(self):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"
        sub = f"user_{get_random_string(5)}"
        private_pem, public_key = _generate_rsa_keypair()

        token = _make_token(
            private_pem,
            issuer=issuer,
            aud=audience, sub=sub)
        oid_config = _oid_config(issuer)

        with patch(
            "jwt.jwks_client.urllib.request.urlopen",
            new=_mock_jwks(public_key)
        ):
            claims = lib.verify_jws(
                token=token,
                audience=audience,
                openid_configuration=oid_config)

        self.assertEqual(claims["iss"], issuer)
        self.assertEqual(claims["aud"], audience)
        self.assertEqual(claims["sub"], sub)

    def test_verify_jws_invalid_audience_raises_suspiciousoperation(self):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"
        private_pem, public_key = _generate_rsa_keypair()

        token = _make_token(
            private_pem,
            issuer=issuer,
            aud=f"{get_random_string(12)}")
        oid_config = _oid_config(issuer)

        with patch(
            "jwt.jwks_client.urllib.request.urlopen",
            new=_mock_jwks(public_key)
        ):
            with self.assertRaisesRegex(SuspiciousOperation, r"Invalid ID token 'aud'"):
                lib.verify_jws(
                    token=token,
                    audience=audience,
                    openid_configuration=oid_config)

    def test_verify_jws_expired_token_raises_suspiciousoperation(self):
        issuer = "https://issuer.zentral.com"
        audience = "my-client"
        private_pem, public_key = _generate_rsa_keypair()

        now = int(time.time())
        token = _make_token(
            private_pem,
            issuer=issuer,
            aud=audience, exp=now - 1000)
        oid_config = _oid_config(issuer)

        with patch(
            "jwt.jwks_client.urllib.request.urlopen",
            new=_mock_jwks(public_key)
        ):
            with self.assertRaisesRegex(SuspiciousOperation, r"ID token has expired"):
                lib.verify_jws(
                    token=token,
                    audience=audience,
                    openid_configuration=oid_config)
