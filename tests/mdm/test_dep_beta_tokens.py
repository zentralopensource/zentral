from unittest.mock import Mock, patch

from django.test import TestCase

from zentral.contrib.mdm.dep import get_dep_virtual_server_beta_tokens
from zentral.contrib.mdm.dep_client import DEPClient

from .utils import force_dep_virtual_server


# Real shape captured from mdmenrollment.apple.com on a working DEP virtual server:
# {"betaEnrollmentTokens": [{"token": ..., "title": ..., "os": ...}, ...]}.
# `os` uses Apple's vocabulary (iOS, OSX, tvOS, visionOS, watchOS, homePodOS).
SAMPLE_RESPONSE = {
    "betaEnrollmentTokens": [
        {"token": "ios26", "title": "iOS 26 AppleSeed Beta", "os": "iOS"},
        {"token": "ios18", "title": "iOS 18 AppleSeed Beta", "os": "iOS"},
        {"token": "macSeq", "title": "macOS Sequoia AppleSeed Beta", "os": "OSX"},
        {"token": "visionos26", "title": "visionOS 26 AppleSeed Beta", "os": "visionOS"},
    ]
}


class TestDEPClientBetaEnrollmentTokens(TestCase):
    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_os_beta_enrollment_tokens(self, send_request):
        send_request.return_value = SAMPLE_RESPONSE
        client = DEPClient("ck", "cs", "at", "as")
        result = client.get_os_beta_enrollment_tokens()
        send_request.assert_called_once_with('os-beta-enrollment/tokens')
        self.assertEqual(result, SAMPLE_RESPONSE)


class TestBetaTokenFetcher(TestCase):
    def _client_mock(self, response):
        client = Mock()
        client.get_os_beta_enrollment_tokens.return_value = response
        return client

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_normalises_response_to_token_list(self, from_vs):
        from_vs.return_value = self._client_mock(SAMPLE_RESPONSE)
        server = force_dep_virtual_server()

        tokens = get_dep_virtual_server_beta_tokens(server)

        self.assertEqual(len(tokens), 4)
        self.assertEqual(tokens[0], {"os": "iOS", "title": "iOS 26 AppleSeed Beta", "token": "ios26"})
        # Apple's vocabulary preserved verbatim
        os_values = {entry["os"] for entry in tokens}
        self.assertEqual(os_values, {"iOS", "OSX", "visionOS"})

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_skips_malformed_entries(self, from_vs):
        from_vs.return_value = self._client_mock({"betaEnrollmentTokens": [
            {"token": "ok", "title": "x", "os": "iOS"},
            {"title": "no token"},
            {"token": "no os", "title": "x"},
            "not a dict",
        ]})
        server = force_dep_virtual_server()
        tokens = get_dep_virtual_server_beta_tokens(server)
        self.assertEqual(tokens, [{"os": "iOS", "title": "x", "token": "ok"}])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_handles_empty_response(self, from_vs):
        from_vs.return_value = self._client_mock({"betaEnrollmentTokens": []})
        server = force_dep_virtual_server()
        self.assertEqual(get_dep_virtual_server_beta_tokens(server), [])

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    def test_each_call_hits_apple(self, from_vs):
        from_vs.return_value = self._client_mock(SAMPLE_RESPONSE)
        server = force_dep_virtual_server()

        get_dep_virtual_server_beta_tokens(server)
        get_dep_virtual_server_beta_tokens(server)

        # No caching — each call instantiates a fresh client and re-fetches
        self.assertEqual(from_vs.call_count, 2)
