from unittest.mock import MagicMock, patch

import httpx
import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)
from django.test import SimpleTestCase
from django.utils.crypto import get_random_string

from zentral.contrib.munki.utils import (
    DEVICECHECK_BASE_URL,
    DEVICECHECK_SANDBOX_BASE_URL,
    validate_device_token_with_apple,
)


def make_ec_private_key_pem():
    """Generate a real P-256 private key in PEM/PKCS8 format — same as Apple's .p8 files."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode()


def make_mock_configuration(sandbox=False):
    cfg = MagicMock()
    cfg.pk = 1
    cfg.devicecheck_team_id = get_random_string(10)
    cfg.devicecheck_private_key_id = get_random_string(10)
    cfg.devicecheck_sandbox = sandbox
    cfg.get_devicecheck_private_key.return_value = make_ec_private_key_pem()
    return cfg


class ValidateDeviceTokenWithAppleTestCase(SimpleTestCase):

    # --- return values ---

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_returns_true_on_200(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        result = validate_device_token_with_apple(make_mock_configuration(), "token_abc")
        self.assertTrue(result)

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_returns_false_on_400(self, mock_post):
        mock_post.return_value = MagicMock(status_code=400, text="Invalid device token")
        result = validate_device_token_with_apple(make_mock_configuration(), "token_abc")
        self.assertFalse(result)

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_returns_none_on_unexpected_status(self, mock_post):
        mock_post.return_value = MagicMock(status_code=500, text="Server Error")
        result = validate_device_token_with_apple(make_mock_configuration(), "token_abc")
        self.assertIsNone(result)

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_returns_none_on_request_error(self, mock_post):
        mock_post.side_effect = httpx.RequestError("connection refused")
        result = validate_device_token_with_apple(make_mock_configuration(), "token_abc")
        self.assertIsNone(result)

    # --- URL selection ---

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_uses_production_url(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        validate_device_token_with_apple(make_mock_configuration(sandbox=False), "token_abc")
        url = mock_post.call_args.args[0]
        self.assertTrue(url.startswith(DEVICECHECK_BASE_URL))

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_uses_sandbox_url(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        validate_device_token_with_apple(make_mock_configuration(sandbox=True), "token_abc")
        url = mock_post.call_args.args[0]
        self.assertTrue(url.startswith(DEVICECHECK_SANDBOX_BASE_URL))

    # --- request payload ---

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_request_payload_contains_device_token(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        device_token = get_random_string(64)
        validate_device_token_with_apple(make_mock_configuration(), device_token)
        payload = mock_post.call_args.kwargs["json"]
        self.assertEqual(payload["device_token"], device_token)
        self.assertIn("transaction_id", payload)
        self.assertIn("timestamp", payload)

    # --- JWT ---

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_authorization_header_is_bearer_jwt(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        validate_device_token_with_apple(make_mock_configuration(), "token_abc")
        auth = mock_post.call_args.kwargs["headers"]["Authorization"]
        self.assertTrue(auth.startswith("Bearer "))

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_jwt_header_alg_and_kid(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        cfg = make_mock_configuration()
        validate_device_token_with_apple(cfg, "token_abc")
        token = mock_post.call_args.kwargs["headers"]["Authorization"].split(" ", 1)[1]
        header = pyjwt.get_unverified_header(token)
        self.assertEqual(header["alg"], "ES256")
        self.assertEqual(header["kid"], cfg.devicecheck_private_key_id)

    @patch("zentral.contrib.munki.utils.httpx.post")
    def test_jwt_iss_claim_matches_team_id(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)
        cfg = make_mock_configuration()
        pem = cfg.get_devicecheck_private_key.return_value
        validate_device_token_with_apple(cfg, "token_abc")
        token = mock_post.call_args.kwargs["headers"]["Authorization"].split(" ", 1)[1]
        public_key = load_pem_private_key(pem.encode(), password=None).public_key()
        claims = pyjwt.decode(token, public_key, algorithms=["ES256"])
        self.assertEqual(claims["iss"], cfg.devicecheck_team_id)
        self.assertIn("iat", claims)
