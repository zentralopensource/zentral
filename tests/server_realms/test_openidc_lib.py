from unittest.mock import patch
from urllib.parse import parse_qs

from django.core.exceptions import SuspiciousOperation
from django.test import SimpleTestCase
import requests
import responses

from realms.backends.openidc.lib import get_claims
from realms.exceptions import RealmUserError


OPENID_CONFIGURATION = {
    "issuer": "https://issuer.example.com",
    "token_endpoint": "https://issuer.example.com/token",
    "userinfo_endpoint": "https://issuer.example.com/userinfo",
}

TOKEN_URL = "https://issuer.example.com/token"
USERINFO_URL = "https://issuer.example.com/userinfo"

# a redirect target that is not registered: following a redirect would raise a ConnectionError
REDIRECT_HEADERS = {"Location": "http://169.254.169.254/latest/meta-data/"}


def response_kwargs(status=200, json=None, body=None):
    kwargs = {"status": status}
    if body is not None:
        kwargs["body"] = body
    else:
        kwargs["json"] = json
    if 300 <= status < 400:
        kwargs["headers"] = REDIRECT_HEADERS
    return kwargs


@patch("realms.backends.openidc.lib.verify_jws")
@patch("realms.backends.openidc.lib.get_openid_configuration")
class OpenIDCLibTestCase(SimpleTestCase):
    def _get_claims(self, get_openid_configuration, verify_jws,
                    token=None, userinfo=None, register=("token", "userinfo"), **cfg):
        if verify_jws.side_effect is None:
            verify_jws.return_value = {"sub": "yolo", "nonce": "the-nonce"}
        if get_openid_configuration.side_effect is None:
            get_openid_configuration.return_value = {**OPENID_CONFIGURATION, **cfg}
        with responses.RequestsMock(assert_all_requests_are_fired=True) as rsps:
            if "token" in register:
                rsps.post(TOKEN_URL, **response_kwargs(**(token or {"json": {"id_token": "id",
                                                                             "access_token": "access"}})))
            if "userinfo" in register:
                rsps.get(USERINFO_URL, **response_kwargs(**(userinfo or {"json": {"sub": "yolo",
                                                                                  "email": "yolo@example.com"}})))
            try:
                claims = get_claims(
                    "https://issuer.example.com/.well-known/openid-configuration",
                    "client-id", "https://zentral/redirect", "the-code", "the-secret", None, "the-nonce",
                )
            finally:
                self.calls = list(rsps.calls)
        return claims

    def _assert_userinfo_skipped(self, get_openid_configuration, verify_jws, reason, **kwargs):
        with self.assertLogs("server.realms.backends.openidc.lib", level="WARNING") as cm:
            claims = self._get_claims(get_openid_configuration, verify_jws, **kwargs)
        self.assertEqual(cm.output,
                         [f"WARNING:server.realms.backends.openidc.lib:UserInfo response skipped: {reason}"])
        return claims

    def test_claims_with_userinfo(self, get_openid_configuration, verify_jws):
        self.assertEqual(
            self._get_claims(get_openid_configuration, verify_jws),
            {"sub": "yolo", "nonce": "the-nonce", "email": "yolo@example.com"}
        )
        self.assertEqual(len(self.calls), 2)
        token_request, userinfo_request = (call.request for call in self.calls)
        self.assertEqual((token_request.method, token_request.url), ("POST", TOKEN_URL))
        self.assertEqual(
            parse_qs(token_request.body),
            {"client_id": ["client-id"],
             "redirect_uri": ["https://zentral/redirect"],
             "grant_type": ["authorization_code"],
             "code": ["the-code"],
             "client_secret": ["the-secret"]},
        )
        self.assertEqual((userinfo_request.method, userinfo_request.url), ("GET", USERINFO_URL))
        self.assertEqual(userinfo_request.headers["Accept"], "application/json")
        self.assertEqual(userinfo_request.headers["Authorization"], "Bearer access")

    def test_discovery_errors(self, get_openid_configuration, verify_jws):
        for side_effect in (requests.Timeout("Boom!!!"), ValueError("Boom!!!")):
            get_openid_configuration.side_effect = side_effect
            with self.assertRaisesRegex(RealmUserError, "^Could not get the OpenID configuration$"):
                self._get_claims(get_openid_configuration, verify_jws, register=())

    def test_token_request_error(self, get_openid_configuration, verify_jws):
        with self.assertRaisesRegex(RealmUserError, "^Could not get the tokens$"):
            self._get_claims(get_openid_configuration, verify_jws, register=("token",),
                             token={"body": requests.Timeout("Boom!!!")})
        verify_jws.assert_not_called()

    def test_userinfo_request_error_skipped(self, get_openid_configuration, verify_jws):
        with self.assertLogs("server.realms.backends.openidc.lib", level="WARNING") as cm:
            claims = self._get_claims(get_openid_configuration, verify_jws,
                                      userinfo={"body": requests.Timeout("Boom!!!")})
        self.assertEqual(claims, {"sub": "yolo", "nonce": "the-nonce"})
        self.assertEqual([r.getMessage() for r in cm.records], ["UserInfo request error"])

    def test_token_endpoint_not_https(self, get_openid_configuration, verify_jws):
        for token_endpoint in (None, "http://issuer.example.com/token", "file:///etc/passwd"):
            with self.assertRaisesRegex(SuspiciousOperation, "The token endpoint does not use https"):
                self._get_claims(get_openid_configuration, verify_jws, register=(), token_endpoint=token_endpoint)

    def test_userinfo_endpoint_not_https(self, get_openid_configuration, verify_jws):
        with self.assertRaisesRegex(SuspiciousOperation, "The userinfo endpoint does not use https"):
            self._get_claims(get_openid_configuration, verify_jws, register=(),
                             userinfo_endpoint="http://issuer.example.com/userinfo")

    def test_no_userinfo_endpoint(self, get_openid_configuration, verify_jws):
        self.assertEqual(
            self._get_claims(get_openid_configuration, verify_jws, register=("token",), userinfo_endpoint=None),
            {"sub": "yolo", "nonce": "the-nonce"}
        )
        self.assertEqual(len(self.calls), 1)

    def test_token_endpoint_error_status(self, get_openid_configuration, verify_jws):
        for token_status in (302, 307, 400, 500):
            with self.assertRaisesRegex(SuspiciousOperation, f"^Token endpoint response status {token_status}$"):
                self._get_claims(get_openid_configuration, verify_jws, register=("token",),
                                 token={"status": token_status, "json": {"error": "invalid_grant"}})
            # a POST is not sent again, and a redirect is not followed
            self.assertEqual(len(self.calls), 1)
        verify_jws.assert_not_called()

    def test_invalid_token_response(self, get_openid_configuration, verify_jws):
        for content in (b"not json", b"[]", b'{"access_token": "access"}', b'{"id_token": 1}'):
            with self.assertRaisesRegex(SuspiciousOperation, "^Invalid token response$"):
                self._get_claims(get_openid_configuration, verify_jws, register=("token",),
                                 token={"body": content})
        verify_jws.assert_not_called()

    def test_userinfo_error_skipped(self, get_openid_configuration, verify_jws):
        for userinfo_status in (302, 429, 503):
            self.assertEqual(
                self._get_claims(get_openid_configuration, verify_jws,
                                 userinfo={"status": userinfo_status, "json": {"sub": "yolo"}}),
                {"sub": "yolo", "nonce": "the-nonce"}
            )
            # the token request, the userinfo request, and its retry on a 429 or a 503
            self.assertEqual(len(self.calls), 2 if userinfo_status == 302 else 3)

    def test_userinfo_not_json_skipped(self, get_openid_configuration, verify_jws):
        # a signed userinfo response
        self.assertEqual(
            self._assert_userinfo_skipped(get_openid_configuration, verify_jws, "it is not JSON",
                                          userinfo={"body": b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ5b2xvIn0.c2ln"}),
            {"sub": "yolo", "nonce": "the-nonce"}
        )

    def test_userinfo_not_a_json_object_skipped(self, get_openid_configuration, verify_jws):
        self.assertEqual(
            self._assert_userinfo_skipped(get_openid_configuration, verify_jws, "it is not a JSON object",
                                          userinfo={"json": ["yolo@example.com"]}),
            {"sub": "yolo", "nonce": "the-nonce"}
        )

    def test_userinfo_sub_mismatch_skipped(self, get_openid_configuration, verify_jws):
        for userinfo in ({"sub": "another-sub", "email": "yolo@example.com"},
                         {"email": "yolo@example.com"}):
            self.assertEqual(
                self._assert_userinfo_skipped(get_openid_configuration, verify_jws,
                                              "its sub is not the sub of the ID token",
                                              userinfo={"json": userinfo}),
                {"sub": "yolo", "nonce": "the-nonce"}
            )

    def test_userinfo_no_id_token_sub_skipped(self, get_openid_configuration, verify_jws):
        verify_jws.side_effect = lambda **kwargs: {"nonce": "the-nonce"}
        self.assertEqual(
            self._assert_userinfo_skipped(get_openid_configuration, verify_jws, "the ID token has no sub"),
            {"nonce": "the-nonce"}
        )
