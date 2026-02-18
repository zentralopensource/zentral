from unittest.mock import Mock, patch

from django.core.exceptions import SuspiciousOperation
from django.test import TestCase

import jwt

from ee.server.realms.backends.openidc import lib as openidc_lib


class VerifyJWSMappingTestCase(TestCase):
    def test_verify_jws_maps_pyjwt_errors_to_suspiciousoperation(self):
        openid_configuration = {"issuer": "https://issuer.zentral.com"}

        cases = [
            (jwt.ExpiredSignatureError(), "ID token has expired"),
            (jwt.ImmatureSignatureError(), "ID token not valid yet"),
            (jwt.InvalidIssuerError(), "Invalid ID token 'iss'"),
            (jwt.InvalidAudienceError(), "Invalid ID token 'aud'"),
            (jwt.InvalidAlgorithmError(), "Unexpected ID token signature algorithm"),
            (jwt.InvalidSignatureError(), "Invalid ID token signature"),
            (jwt.DecodeError("bad"), "Invalid ID token signature"),
            (jwt.PyJWTError("bad"), "Invalid ID token signature"),
        ]

        for exc, msg in cases:
            with self.subTest(exc=exc.__class__.__name__):
                with patch.object(openidc_lib, "_verify_jws", side_effect=exc):
                    with self.assertRaises(SuspiciousOperation) as ctx:
                        openidc_lib.verify_jws("token", "client_id", openid_configuration)
                    self.assertEqual(str(ctx.exception), msg)

    def test_verify_jws_maps_missing_required_claims(self):
        openid_configuration = {"issuer": "https://issuer.zentral.com"}

        e_iss = jwt.MissingRequiredClaimError("iss")
        e_aud = jwt.MissingRequiredClaimError("aud")
        e_other = jwt.MissingRequiredClaimError("exp")

        for exc, msg in [
            (e_iss, "Invalid ID token 'iss'"),
            (e_aud, "Invalid ID token 'aud'"),
            (e_other, "Invalid ID token signature"),
        ]:
            with self.subTest(claim=getattr(exc, "claim", None)):
                with patch.object(openidc_lib, "_verify_jws", side_effect=exc):
                    with self.assertRaises(SuspiciousOperation) as ctx:
                        openidc_lib.verify_jws("token", "client_id", openid_configuration)
                    self.assertEqual(str(ctx.exception), msg)


class VerifyJWSWithDiscoveryTestCase(TestCase):
    def test_verify_jws_with_discovery_fetches_config_and_calls_verify(self):
        issuer_uri = "https://issuer.zentral.com/"
        expected_discovery = "https://issuer.zentral.com/.well-known/openid-configuration"
        audience = "my-aud"
        token = "header.payload.sig"

        oid_config = {
            "issuer": "https://issuer.zentral.com",
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        claims = {"sub": "abc"}

        with patch.object(openidc_lib, "_get_openid_configuration", return_value=oid_config) as get_cfg_mock, \
             patch.object(openidc_lib, "_verify_jws", return_value=claims) as verify_mock:
            out = openidc_lib.verify_jws_with_discovery(token=token, audience=audience, issuer_uri=issuer_uri)

        self.assertEqual(out, claims)
        get_cfg_mock.assert_called_once_with(expected_discovery)
        verify_mock.assert_called_once()
        _, kwargs = verify_mock.call_args
        self.assertEqual(kwargs["token"], token)
        self.assertEqual(kwargs["issuer"], "https://issuer.zentral.com/")
        self.assertEqual(kwargs["audience"], audience)
        self.assertEqual(kwargs["oid_config"], oid_config)


class InternalVerifyJWSTestCase(TestCase):
    def test__verify_jws_rejects_none_algorithm(self):
        oid_config = {
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        with patch.object(openidc_lib.jwt, "get_unverified_header", return_value={"alg": "none"}):
            with self.assertRaises(SuspiciousOperation) as ctx:
                openidc_lib._verify_jws("t", "https://issuer.zentral.com", "aud", oid_config)
        self.assertEqual(str(ctx.exception), "ID token is not signed")

    def test__verify_jws_rejects_unexpected_algorithm(self):
        oid_config = {
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["ES256"],
        }
        with patch.object(openidc_lib.jwt, "get_unverified_header", return_value={"alg": "RS256"}):
            with self.assertRaises(SuspiciousOperation) as ctx:
                openidc_lib._verify_jws(
                    token="t",
                    audience="aud",
                    issuer="https://issuer.zentral.com",
                    oid_config=oid_config)
        self.assertEqual(str(ctx.exception), "Could not find ID token signing key")

    def test__verify_jws_rejects_if_supported_contains_none(self):
        oid_config = {
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["none", "RS256"],
        }
        with patch.object(openidc_lib.jwt, "get_unverified_header", return_value={"alg": "RS256"}):
            with self.assertRaises(SuspiciousOperation) as ctx:
                openidc_lib._verify_jws("t", "https://issuer.zentral.com", "aud", oid_config)
        self.assertEqual(str(ctx.exception), "Could not find ID token signing key")

    def test__verify_jws_raises_if_signing_key_not_found(self):
        oid_config = {
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        with patch.object(openidc_lib.jwt, "get_unverified_header", return_value={"alg": "RS256"}), \
             patch.object(openidc_lib, "PyJWKClient", side_effect=Exception("boom")):
            with self.assertRaises(SuspiciousOperation) as ctx:
                openidc_lib._verify_jws("t", "https://issuer.zentral.com", "aud", oid_config)
        self.assertEqual(str(ctx.exception), "Could not find ID token signing key")

    def test__verify_jws_success_calls_jwt_decode_with_expected_params(self):
        token = "header.payload.sig"
        issuer = "https://issuer.zentral.com"
        audience = "my-aud"
        oid_config = {
            "jwks_uri": "https://issuer.zentral.com/jwks",
            "id_token_signing_alg_values_supported": ["RS256"],
        }

        jwk_client = Mock()
        jwk_client.get_signing_key_from_jwt.return_value = Mock(key="PUBKEY")

        decode_mock = Mock(return_value={"sub": "abc"})

        with patch.object(openidc_lib.jwt, "get_unverified_header", return_value={"alg": "RS256"}), \
             patch.object(openidc_lib, "PyJWKClient", return_value=jwk_client), \
             patch.object(openidc_lib.jwt, "decode", decode_mock):
            claims = openidc_lib._verify_jws(
                token=token,
                audience=audience,
                issuer=issuer,
                oid_config=oid_config)

        self.assertEqual(claims, {"sub": "abc"})
        jwk_client.get_signing_key_from_jwt.assert_called_once_with(token)

        decode_mock.assert_called_once()
        _, kwargs = decode_mock.call_args
        self.assertEqual(kwargs["key"], "PUBKEY")
        self.assertEqual(kwargs["algorithms"], ["RS256"])
        self.assertEqual(kwargs["audience"], audience)
        self.assertEqual(kwargs["issuer"], issuer)
        self.assertEqual(kwargs["leeway"], openidc_lib.TIMESTAMP_LEEWAY)
        self.assertEqual(kwargs["options"]["require"], ["iss", "aud"])
