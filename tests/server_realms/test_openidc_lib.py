from unittest.mock import patch

from django.core.exceptions import SuspiciousOperation
from django.test import SimpleTestCase
import requests
from requests import Response

from realms.backends.openidc.lib import get_claims
from realms.exceptions import RealmUserError


def make_response(status_code, content):
    response = Response()
    response.status_code = status_code
    response._content = content
    return response


OPENID_CONFIGURATION = {
    "issuer": "https://issuer.example.com",
    "token_endpoint": "https://issuer.example.com/token",
    "userinfo_endpoint": "https://issuer.example.com/userinfo",
}


@patch("realms.backends.openidc.lib.verify_jws")
@patch("requests.Session.get")
@patch("requests.Session.post")
@patch("realms.backends.openidc.lib.get_openid_configuration")
class OpenIDCLibTestCase(SimpleTestCase):
    def _get_claims(self):
        return get_claims(
            "https://issuer.example.com/.well-known/openid-configuration",
            "client-id", "https://zentral/redirect", "the-code", "the-secret", None, "the-nonce",
        )

    def _setup(self, get_openid_configuration, post, get, verify_jws,
               userinfo_status=200, **cfg):
        verify_jws.return_value = {"sub": "yolo", "nonce": "the-nonce"}
        get_openid_configuration.return_value = {**OPENID_CONFIGURATION, **cfg}
        post.return_value.status_code = 200
        post.return_value.json.return_value = {"id_token": "id", "access_token": "access"}
        get.return_value.status_code = userinfo_status
        get.return_value.json.return_value = {"sub": "yolo", "email": "yolo@example.com"}

    def test_claims_with_userinfo(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        self.assertEqual(self._get_claims(), {"sub": "yolo", "nonce": "the-nonce", "email": "yolo@example.com"})
        self.assertEqual(post.call_args.args, ("https://issuer.example.com/token",))
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertEqual(get.call_args.args, ("https://issuer.example.com/userinfo",))
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_discovery_errors(self, get_openid_configuration, post, get, verify_jws):
        for side_effect in (requests.Timeout("Boom!!!"), ValueError("Boom!!!")):
            get_openid_configuration.side_effect = side_effect
            with self.assertRaisesRegex(RealmUserError, "^Could not get the OpenID configuration$"):
                self._get_claims()
        post.assert_not_called()

    def test_token_request_error(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        post.side_effect = requests.Timeout("Boom!!!")
        with self.assertRaisesRegex(RealmUserError, "^Could not get the tokens$"):
            self._get_claims()
        verify_jws.assert_not_called()

    def test_userinfo_request_error_skipped(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        get.side_effect = requests.Timeout("Boom!!!")
        with self.assertLogs("server.realms.backends.openidc.lib", level="WARNING") as cm:
            self.assertEqual(self._get_claims(), {"sub": "yolo", "nonce": "the-nonce"})
        self.assertEqual([r.getMessage() for r in cm.records], ["UserInfo request error"])

    def test_token_endpoint_not_https(self, get_openid_configuration, post, get, verify_jws):
        for token_endpoint in (None, "http://issuer.example.com/token", "file:///etc/passwd"):
            self._setup(get_openid_configuration, post, get, verify_jws, token_endpoint=token_endpoint)
            with self.assertRaisesRegex(SuspiciousOperation, "The token endpoint does not use https"):
                self._get_claims()
        post.assert_not_called()

    def test_userinfo_endpoint_not_https(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws,
                    userinfo_endpoint="http://issuer.example.com/userinfo")
        with self.assertRaisesRegex(SuspiciousOperation, "The userinfo endpoint does not use https"):
            self._get_claims()
        post.assert_not_called()
        get.assert_not_called()

    def test_no_userinfo_endpoint(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        get_openid_configuration.return_value.pop("userinfo_endpoint")
        self.assertEqual(self._get_claims(), {"sub": "yolo", "nonce": "the-nonce"})
        get.assert_not_called()

    def test_token_endpoint_error_status(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        for token_status in (307, 400, 500):
            post.return_value = make_response(token_status, b'{"error": "invalid_grant"}')
            with self.assertRaisesRegex(SuspiciousOperation, f"^Token endpoint response status {token_status}$"):
                self._get_claims()
        verify_jws.assert_not_called()

    def test_invalid_token_response(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        for content in (b"not json", b"[]", b'{"access_token": "access"}', b'{"id_token": 1}'):
            post.return_value = make_response(200, content)
            with self.assertRaisesRegex(SuspiciousOperation, "^Invalid token response$"):
                self._get_claims()
        verify_jws.assert_not_called()

    def test_userinfo_error_skipped(self, get_openid_configuration, post, get, verify_jws):
        for userinfo_status in (302, 429, 503):
            self._setup(get_openid_configuration, post, get, verify_jws, userinfo_status=userinfo_status)
            self.assertEqual(self._get_claims(), {"sub": "yolo", "nonce": "the-nonce"})

    def _assert_userinfo_skipped(self, reason):
        with self.assertLogs("server.realms.backends.openidc.lib", level="WARNING") as cm:
            claims = self._get_claims()
        self.assertEqual(cm.output,
                         [f"WARNING:server.realms.backends.openidc.lib:UserInfo response skipped: {reason}"])
        return claims

    def test_userinfo_not_json_skipped(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        # a signed userinfo response
        get.return_value = make_response(200, b"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ5b2xvIn0.c2ln")
        self.assertEqual(
            self._assert_userinfo_skipped("it is not JSON"),
            {"sub": "yolo", "nonce": "the-nonce"}
        )

    def test_userinfo_not_a_json_object_skipped(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        get.return_value.json.return_value = ["yolo@example.com"]
        self.assertEqual(
            self._assert_userinfo_skipped("it is not a JSON object"),
            {"sub": "yolo", "nonce": "the-nonce"}
        )

    def test_userinfo_sub_mismatch_skipped(self, get_openid_configuration, post, get, verify_jws):
        for userinfo in ({"sub": "another-sub", "email": "yolo@example.com"},
                         {"email": "yolo@example.com"}):
            self._setup(get_openid_configuration, post, get, verify_jws)
            get.return_value.json.return_value = userinfo
            self.assertEqual(
                self._assert_userinfo_skipped("its sub is not the sub of the ID token"),
                {"sub": "yolo", "nonce": "the-nonce"}
            )

    def test_userinfo_no_id_token_sub_skipped(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        verify_jws.return_value = {"nonce": "the-nonce"}
        self.assertEqual(
            self._assert_userinfo_skipped("the ID token has no sub"),
            {"nonce": "the-nonce"}
        )
