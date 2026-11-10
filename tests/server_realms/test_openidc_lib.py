from unittest.mock import patch

from django.test import SimpleTestCase
import requests

from realms.backends.openidc.lib import get_claims
from realms.exceptions import RealmUserError


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
            "client-id", "https://zentral/redirect", "the-code", "the-secret", None,
        )

    def _setup(self, get_openid_configuration, post, get, verify_jws,
               userinfo_status=200, **cfg):
        verify_jws.return_value = {"sub": "yolo"}
        get_openid_configuration.return_value = {**OPENID_CONFIGURATION, **cfg}
        post.return_value.status_code = 200
        post.return_value.json.return_value = {"id_token": "id", "access_token": "access"}
        get.return_value.status_code = userinfo_status
        get.return_value.json.return_value = {"sub": "yolo", "email": "yolo@example.com"}

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
            self.assertEqual(self._get_claims(), {"sub": "yolo"})
        self.assertEqual([r.getMessage() for r in cm.records], ["UserInfo request error"])

    def test_no_userinfo_endpoint(self, get_openid_configuration, post, get, verify_jws):
        self._setup(get_openid_configuration, post, get, verify_jws)
        get_openid_configuration.return_value.pop("userinfo_endpoint")
        self.assertEqual(self._get_claims(), {"sub": "yolo"})
        get.assert_not_called()
