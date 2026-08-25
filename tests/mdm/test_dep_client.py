from unittest.mock import Mock, patch

from base.utils import deployment_info
from django.test import TestCase
from requests import RequestException

from zentral.contrib.mdm.dep_client import (
    DEFAULT_PAGINATION_LIMIT,
    DEVICE_BATCH_SIZE,
    DEPClient,
    DEPClientError,
)


# what /account really answers, trimmed to the urls that matter here
ACCOUNT_DETAIL = {
    "org_name": "Yolo",
    "server_uuid": "00000000000000000000000000000000",
    "urls": [
        {"uri": "/session", "http_method": ["GET"]},
        {"uri": "/devices", "http_method": ["POST"]},
        {"uri": "/server/devices", "http_method": ["POST"], "limit": {"default": 1000, "maximum": 1000}},
        {"uri": "/devices/sync", "http_method": ["POST"], "limit": {"default": 1000, "maximum": 1000}},
        {"uri": "/profile/devices", "http_method": ["DELETE", "POST", "PUT"]},
        {"uri": "/devices/disown", "http_method": ["POST"]},
    ],
}


def build_client():
    return DEPClient("consumer-key", "consumer-secret", "access-token", "access-secret")


def build_serial_numbers(count):
    return [f"SN{idx:08d}" for idx in range(count)]


class TestDEPClientAccountLimits(TestCase):
    maxDiff = None

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_uri_limit(self, send_request):
        send_request.return_value = ACCOUNT_DETAIL
        client = build_client()
        # advertised
        self.assertEqual(client.get_uri_limit("/server/devices"), 1000)
        self.assertEqual(client.get_uri_limit("/devices/sync"), 1000)
        # listed, but with no limit
        self.assertIsNone(client.get_uri_limit("/devices"))
        self.assertIsNone(client.get_uri_limit("/profile/devices"))
        self.assertIsNone(client.get_uri_limit("/devices/disown"))
        # not listed at all
        self.assertIsNone(client.get_uri_limit("/yolo"))
        # the account detail is read once, not once per lookup
        send_request.assert_called_once_with('account')

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_fetch_devices_pages_at_the_advertised_maximum(self, send_request):
        send_request.side_effect = [
            ACCOUNT_DETAIL,
            {"devices": [], "more_to_follow": False, "cursor": "yolo"},
        ]
        list(build_client().fetch_devices())
        self.assertEqual(send_request.call_args_list[0].args, ('account',))
        self.assertEqual(send_request.call_args_list[1].kwargs["json"], {"limit": 1000})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_sync_devices_pages_at_the_advertised_maximum(self, send_request):
        send_request.side_effect = [
            ACCOUNT_DETAIL,
            {"devices": [], "more_to_follow": False, "cursor": "fomo"},
        ]
        list(build_client().sync_devices("yolo"))
        self.assertEqual(send_request.call_args_list[1].kwargs["json"],
                         {"limit": 1000, "cursor": "yolo"})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_pagination_falls_back_when_nothing_is_advertised(self, send_request):
        send_request.side_effect = [
            {"org_name": "Zentral", "urls": [{"uri": "/server/devices", "http_method": ["POST"]}]},
            {"devices": [], "more_to_follow": False, "cursor": "yolo"},
        ]
        list(build_client().fetch_devices())
        self.assertEqual(send_request.call_args_list[1].kwargs["json"],
                         {"limit": DEFAULT_PAGINATION_LIMIT})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_pagination_falls_back_when_the_account_detail_fails(self, send_request):
        send_request.side_effect = [
            DEPClientError("Could not perform operation", status_code=500),
            {"devices": [], "more_to_follow": False, "cursor": "yolo"},
        ]
        # a virtual server whose account detail cannot be read still synchronizes
        list(build_client().fetch_devices())
        self.assertEqual(send_request.call_args_list[1].kwargs["json"],
                         {"limit": DEFAULT_PAGINATION_LIMIT})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_uri_limit_tolerates_an_account_detail_that_is_not_json(self, send_request):
        # send_request returns response.content when the body does not parse as JSON, so the
        # account detail is not always a dict
        send_request.return_value = b"<html>Service unavailable</html>"
        client = build_client()
        self.assertIsNone(client.get_uri_limit("/server/devices"))
        self.assertEqual(client.get_pagination_limit("server/devices"), DEFAULT_PAGINATION_LIMIT)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_account_detail_is_dropped_with_the_auth_session(self, send_request):
        send_request.return_value = ACCOUNT_DETAIL
        client = build_client()
        session_response = Mock()
        session_response.json.return_value = {"auth_session_token": "yolo"}
        client.oauth_session = Mock()
        client.oauth_session.get.return_value = session_response

        self.assertEqual(client.get_uri_limit("/server/devices"), 1000)
        self.assertEqual(client.get_uri_limit("/server/devices"), 1000)
        self.assertEqual(len(send_request.call_args_list), 1)

        # a renewed session may describe a different account, so what it advertised goes with it
        client.get_auth_session_token(renew=True)
        self.assertEqual(client.get_uri_limit("/server/devices"), 1000)
        self.assertEqual(len(send_request.call_args_list), 2)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_device_batch_size_is_not_worth_a_request_of_its_own(self, send_request):
        send_request.return_value = ACCOUNT_DETAIL
        # a single device operation does not pay a round trip to size a batch of one
        self.assertEqual(build_client().get_device_batch_size("/devices"), DEVICE_BATCH_SIZE)
        send_request.assert_not_called()

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_device_batch_size_falls_back_when_nothing_is_advertised(self, send_request):
        send_request.return_value = ACCOUNT_DETAIL
        client = build_client()
        client.get_account()
        # none of the device array endpoints advertises a limit today
        for uri in ("/devices", "/profile/devices", "/devices/disown", "/profile"):
            self.assertEqual(client.get_device_batch_size(uri), DEVICE_BATCH_SIZE)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_device_batch_size_honours_an_advertised_limit(self, send_request):
        # an account that does advertise one for a device array endpoint is obeyed, not overrun
        send_request.return_value = {
            "urls": [{"uri": "/profile/devices", "http_method": ["POST"],
                      "limit": {"default": 250, "maximum": 250}}]
        }
        client = build_client()
        client.get_account()
        self.assertEqual(client.get_device_batch_size("/profile/devices"), 250)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_splits_at_the_advertised_limit(self, send_request):
        serial_numbers = build_serial_numbers(3)
        send_request.side_effect = [
            {"urls": [{"uri": "/profile/devices", "http_method": ["POST"],
                       "limit": {"default": 2, "maximum": 2}}]},
            {"devices": {sn: "SUCCESS" for sn in serial_numbers[:2]}},
            {"devices": {serial_numbers[2]: "SUCCESS"}},
        ]
        client = build_client()
        client.get_account()
        response = client.assign_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70", serial_numbers)
        self.assertEqual(send_request.call_args_list[1].kwargs["json"]["devices"], serial_numbers[:2])
        self.assertEqual(send_request.call_args_list[2].kwargs["json"]["devices"], serial_numbers[2:])
        self.assertEqual(len(response["devices"]), 3)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_unreadable_account_detail_logs_what_apple_answered(self, send_request):
        send_request.side_effect = DEPClientError("Could not perform operation",
                                                  error_code="USER_AGENT_INVALID", status_code=400)
        client = build_client()
        with self.assertLogs("zentral.contrib.mdm.dep_client", level="WARNING") as cm:
            # the size falls back to the default, and the reason does not stay silent
            self.assertEqual(client.get_pagination_limit("server/devices"), DEFAULT_PAGINATION_LIMIT)
        self.assertIn("USER_AGENT_INVALID", cm.output[0])

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_explicit_batch_request_limit_wins(self, send_request):
        send_request.return_value = {"devices": [], "more_to_follow": False, "cursor": "yolo"}
        client = DEPClient("ck", "cs", "at", "as", batch_request_limit=7)
        list(client.fetch_devices())
        # Apple is not asked at all
        self.assertEqual(len(send_request.call_args_list), 1)
        self.assertEqual(send_request.call_args_list[0].kwargs["json"], {"limit": 7})


class TestDEPClientDeviceChunks(TestCase):
    maxDiff = None

    def dep_client(self, batch_size=DEVICE_BATCH_SIZE):
        # the limit resolution has its own tests above; here the size is fixed so that the
        # splitting and the merging are the only things under test
        client = build_client()
        client.get_device_batch_size = lambda uri: batch_size
        return client

    # get_devices

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_devices_single_request(self, send_request):
        serial_numbers = build_serial_numbers(2)
        send_request.return_value = {
            "devices": {sn: {"response_status": "SUCCESS", "model": "iPhone X"} for sn in serial_numbers}
        }
        devices = self.dep_client().get_devices(serial_numbers)
        self.assertEqual(sorted(devices), serial_numbers)
        send_request.assert_called_once_with('devices', 'POST', json={"devices": serial_numbers})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_devices_over_the_limit_is_split(self, send_request):
        serial_numbers = build_serial_numbers(DEVICE_BATCH_SIZE + 1)
        send_request.side_effect = [
            {"devices": {sn: {"response_status": "SUCCESS"} for sn in serial_numbers[:DEVICE_BATCH_SIZE]}},
            {"devices": {sn: {"response_status": "SUCCESS"} for sn in serial_numbers[DEVICE_BATCH_SIZE:]}},
        ]
        devices = self.dep_client().get_devices(serial_numbers)
        self.assertEqual(len(send_request.call_args_list), 2)
        self.assertEqual(send_request.call_args_list[0].kwargs["json"],
                         {"devices": serial_numbers[:DEVICE_BATCH_SIZE]})
        self.assertEqual(send_request.call_args_list[1].kwargs["json"],
                         {"devices": serial_numbers[DEVICE_BATCH_SIZE:]})
        self.assertEqual(sorted(devices), serial_numbers)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_devices_skips_the_unsuccessful_ones(self, send_request):
        serial_numbers = build_serial_numbers(2)
        send_request.return_value = {
            "devices": {serial_numbers[0]: {"response_status": "SUCCESS"},
                        serial_numbers[1]: {"response_status": "NOT_ACCESSIBLE"}}
        }
        self.assertEqual(list(self.dep_client().get_devices(serial_numbers)), [serial_numbers[0]])

    # assign_profile

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_single_request(self, send_request):
        serial_numbers = build_serial_numbers(2)
        profile_uuid = "8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70"
        send_request.return_value = {"devices": {sn: "SUCCESS" for sn in serial_numbers}}
        response = self.dep_client().assign_profile(profile_uuid, serial_numbers)
        self.assertEqual(response, {"devices": {sn: "SUCCESS" for sn in serial_numbers}})
        send_request.assert_called_once_with(
            'profile/devices', 'POST',
            json={"devices": serial_numbers, "profile_uuid": "8ECF1F2E2B0A4C1E9A4F2B3C4D5E6F70"}
        )

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_over_the_limit_is_split(self, send_request):
        serial_numbers = build_serial_numbers(DEVICE_BATCH_SIZE + 3)
        send_request.side_effect = [
            {"devices": {sn: "SUCCESS" for sn in serial_numbers[:DEVICE_BATCH_SIZE]}},
            {"devices": {sn: "FAILED" for sn in serial_numbers[DEVICE_BATCH_SIZE:]}},
        ]
        response = self.dep_client().assign_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70", serial_numbers)
        self.assertEqual(len(send_request.call_args_list), 2)
        self.assertEqual(len(send_request.call_args_list[0].kwargs["json"]["devices"]), DEVICE_BATCH_SIZE)
        self.assertEqual(send_request.call_args_list[1].kwargs["json"]["devices"],
                         serial_numbers[DEVICE_BATCH_SIZE:])
        # the statuses of every chunk are merged, the caller cannot tell there were two requests
        self.assertEqual(len(response["devices"]), DEVICE_BATCH_SIZE + 3)
        self.assertEqual(response["devices"][serial_numbers[0]], "SUCCESS")
        self.assertEqual(response["devices"][serial_numbers[-1]], "FAILED")

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_keeps_the_longest_retry_after_seconds(self, send_request):
        serial_numbers = build_serial_numbers(DEVICE_BATCH_SIZE + 3)
        send_request.side_effect = [
            {"devices": {sn: "THROTTLED" for sn in serial_numbers[:DEVICE_BATCH_SIZE]},
             "retry_after_seconds": 60},
            {"devices": {sn: "THROTTLED" for sn in serial_numbers[DEVICE_BATCH_SIZE:]},
             "retry_after_seconds": 300},
        ]
        response = self.dep_client().assign_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70", serial_numbers)
        # one delay per response, and the longest of them covers the throttled devices of all
        self.assertEqual(response["retry_after_seconds"], 300)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_no_retry_after_seconds_no_key(self, send_request):
        serial_numbers = build_serial_numbers(2)
        send_request.return_value = {"devices": {sn: "SUCCESS" for sn in serial_numbers}}
        response = self.dep_client().assign_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70", serial_numbers)
        self.assertNotIn("retry_after_seconds", response)

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_assign_profile_ignores_an_unusable_retry_after_seconds(self, send_request):
        serial_numbers = build_serial_numbers(2)
        send_request.return_value = {"devices": {sn: "THROTTLED" for sn in serial_numbers},
                                     "retry_after_seconds": "soon"}
        response = self.dep_client().assign_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70", serial_numbers)
        self.assertNotIn("retry_after_seconds", response)

    # disown_devices

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_devices_single_request(self, send_request):
        serial_numbers = build_serial_numbers(1)
        send_request.return_value = {"devices": {serial_numbers[0]: "SUCCESS"}}
        response = self.dep_client().disown_devices(serial_numbers)
        self.assertEqual(response, {"devices": {serial_numbers[0]: "SUCCESS"}})
        send_request.assert_called_once_with('devices/disown', 'POST', json={"devices": serial_numbers})

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_disown_devices_over_the_limit_is_split(self, send_request):
        serial_numbers = build_serial_numbers(DEVICE_BATCH_SIZE + 1)
        send_request.side_effect = [
            {"devices": {sn: "SUCCESS" for sn in serial_numbers[:DEVICE_BATCH_SIZE]}},
            {"devices": {sn: "SUCCESS" for sn in serial_numbers[DEVICE_BATCH_SIZE:]}},
        ]
        response = self.dep_client().disown_devices(serial_numbers)
        self.assertEqual(len(send_request.call_args_list), 2)
        self.assertEqual(len(response["devices"]), DEVICE_BATCH_SIZE + 1)


class TestDEPClientSession(TestCase):
    maxDiff = None

    def test_the_sessions_name_zentral_in_the_user_agent(self):
        client = build_client()
        # the service answers USER_AGENT_INVALID to the default user agent of the requests library
        self.assertEqual(client.default_session.headers["User-Agent"], deployment_info.user_agent)
        self.assertEqual(client.oauth_session.headers["User-Agent"], deployment_info.user_agent)
        self.assertTrue(client.default_session.headers["User-Agent"].startswith("Zentral/"))

    def test_the_default_session_carries_the_protocol_version(self):
        client = build_client()
        self.assertEqual(client.default_session.headers["X-Server-Protocol-Version"], "10")


class TestDEPClientTransport(TestCase):
    """The requests layer, which every other test mocks away."""

    maxDiff = None

    def build_client(self):
        client = build_client()
        # the OAuth session and the session that carries the X-ADM-Auth-Session header are the two
        # ends that talk to Apple. The headers dict stays real, it is where the token lives.
        client.oauth_session = Mock()
        client.default_session.request = Mock()
        return client

    @staticmethod
    def build_response(status_code=200, json_data=None, json_error=False, headers=None, content=b"", text=""):
        response = Mock()
        response.status_code = status_code
        response.headers = {} if headers is None else headers
        response.content = content
        response.text = text
        if json_error:
            response.json.side_effect = ValueError("no JSON object could be decoded")
        else:
            response.json.return_value = json_data
        if status_code >= 400:
            response.raise_for_status.side_effect = RequestException(response=response)
        else:
            response.raise_for_status.return_value = None
        return response

    # get_auth_session_token

    def test_get_auth_session_token_reuses_the_current_one(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.get_auth_session_token()
        client.oauth_session.get.assert_not_called()

    def test_get_auth_session_token_renew_asks_for_a_new_one(self):
        client = self.build_client()
        client.auth_session_token = "old"
        client._account = ACCOUNT_DETAIL
        client._limits = {"/devices": 5000}
        client.oauth_session.get.return_value = self.build_response(json_data={"auth_session_token": "new"})
        client.get_auth_session_token(renew=True)
        client.oauth_session.get.assert_called_once_with("https://mdmenrollment.apple.com/session")
        self.assertEqual(client.auth_session_token, "new")
        # the account detail describes the session it came from
        self.assertIsNone(client._account)
        self.assertEqual(client._limits, {})

    def test_get_auth_session_token_terms_not_signed(self):
        client = self.build_client()
        client.oauth_session.get.return_value = self.build_response(status_code=403, text="T_C_NOT_SIGNED\n")
        with self.assertRaises(DEPClientError) as cm:
            client.get_auth_session_token()
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.error_code, "T_C_NOT_SIGNED")
        self.assertEqual(str(cm.exception),
                         "Could not get auth session token, error code: T_C_NOT_SIGNED, status code: 403")

    def test_get_auth_session_token_server_error_has_no_error_code(self):
        client = self.build_client()
        client.oauth_session.get.return_value = self.build_response(status_code=500, text="oops")
        with self.assertRaises(DEPClientError) as cm:
            client.get_auth_session_token()
        self.assertEqual(cm.exception.status_code, 500)
        # only a 403 carries one
        self.assertIsNone(cm.exception.error_code)

    def test_get_auth_session_token_without_a_response(self):
        client = self.build_client()
        client.oauth_session.get.side_effect = RequestException("connection reset by peer")
        with self.assertRaises(DEPClientError) as cm:
            client.get_auth_session_token()
        self.assertIsNone(cm.exception.status_code)
        self.assertIsNone(cm.exception.error_code)
        self.assertEqual(str(cm.exception), "Could not get auth session token")

    # send_request

    def test_send_request_returns_the_json(self):
        client = self.build_client()
        client.auth_session_token = "first"
        client.default_session.request.return_value = self.build_response(json_data={"org_name": "Yolo"})
        self.assertEqual(client.send_request("account"), {"org_name": "Yolo"})
        client.default_session.request.assert_called_once_with(
            "GET", "https://mdmenrollment.apple.com/account", json=None, params={}
        )

    def test_send_request_keeps_the_rotated_session_token(self):
        client = self.build_client()
        client.auth_session_token = "first"
        client.default_session.request.return_value = self.build_response(
            json_data={}, headers={"X-ADM-Auth-Session": "second"}
        )
        client.send_request("account")
        # the service issues a new token in its answers to the other calls
        self.assertEqual(client.auth_session_token, "second")

    def test_send_request_without_a_new_token_keeps_the_current_one(self):
        client = self.build_client()
        client.auth_session_token = "first"
        client.default_session.request.return_value = self.build_response(json_data={})
        client.send_request("account")
        self.assertEqual(client.auth_session_token, "first")

    def test_send_request_falls_back_to_the_body(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.default_session.request.return_value = self.build_response(json_error=True, content=b"<plist/>")
        self.assertEqual(client.send_request("profile", profile_uuid="8ECF"), b"<plist/>")
        client.default_session.request.assert_called_once_with(
            "GET", "https://mdmenrollment.apple.com/profile", json=None, params={"profile_uuid": "8ECF"}
        )

    def test_send_request_posts_the_body(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.default_session.request.return_value = self.build_response(json_data={"devices": []})
        client.send_request("devices", "POST", json={"devices": ["SN00000001"]})
        client.default_session.request.assert_called_once_with(
            "POST", "https://mdmenrollment.apple.com/devices", json={"devices": ["SN00000001"]}, params={}
        )

    def test_send_request_renews_the_session_token_and_retries(self):
        client = self.build_client()
        client.auth_session_token = "expired"
        client.oauth_session.get.return_value = self.build_response(json_data={"auth_session_token": "fresh"})
        client.default_session.request.side_effect = [
            self.build_response(status_code=401),
            self.build_response(json_data={"org_name": "Yolo"}),
        ]
        self.assertEqual(client.send_request("account"), {"org_name": "Yolo"})
        client.oauth_session.get.assert_called_once_with("https://mdmenrollment.apple.com/session")
        self.assertEqual(len(client.default_session.request.call_args_list), 2)
        self.assertEqual(client.auth_session_token, "fresh")

    def test_send_request_gives_up_when_the_new_token_is_refused_too(self):
        client = self.build_client()
        client.auth_session_token = "expired"
        client.oauth_session.get.return_value = self.build_response(status_code=403, text="ACCESS_DENIED")
        client.default_session.request.return_value = self.build_response(status_code=403, text="ACCESS_DENIED")
        with self.assertRaises(DEPClientError) as cm:
            client.send_request("account")
        # the error of the renewal, not of the request it was for
        self.assertEqual(str(cm.exception),
                         "Could not get auth session token, error code: ACCESS_DENIED, status code: 403")

    def test_send_request_bad_request_carries_the_error_code(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.default_session.request.return_value = self.build_response(
            status_code=400, text="DEVICE_NOT_FOUND\n"
        )
        with self.assertRaises(DEPClientError) as cm:
            client.send_request("device/replacementDetails", device="SN00000001")
        self.assertEqual(cm.exception.status_code, 400)
        self.assertEqual(cm.exception.error_code, "DEVICE_NOT_FOUND")

    def test_send_request_server_error_has_no_error_code(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.default_session.request.return_value = self.build_response(status_code=503, text="Try again")
        with self.assertRaises(DEPClientError) as cm:
            client.send_request("account")
        self.assertEqual(cm.exception.status_code, 503)
        self.assertIsNone(cm.exception.error_code)
        self.assertEqual(str(cm.exception), "Could not perform operation, status code: 503")

    def test_send_request_without_a_response(self):
        client = self.build_client()
        client.auth_session_token = "yolo"
        client.default_session.request.side_effect = RequestException("connection reset by peer")
        with self.assertRaises(DEPClientError) as cm:
            client.send_request("account")
        self.assertIsNone(cm.exception.status_code)
        self.assertIsNone(cm.exception.error_code)

    def test_send_request_asks_for_a_session_token_first(self):
        client = self.build_client()
        client.oauth_session.get.return_value = self.build_response(json_data={"auth_session_token": "first"})
        client.default_session.request.return_value = self.build_response(json_data={})
        client.send_request("account")
        client.oauth_session.get.assert_called_once_with("https://mdmenrollment.apple.com/session")
        self.assertEqual(client.default_session.headers["X-ADM-Auth-Session"], "first")

    # profiles

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_get_profile(self, send_request):
        send_request.return_value = {"profile_name": "yolo"}
        response = build_client().get_profile("8ecf1f2e-2b0a-4c1e-9a4f-2b3c4d5e6f70")
        self.assertEqual(response, {"profile_name": "yolo"})
        send_request.assert_called_once_with('profile', profile_uuid="8ECF1F2E2B0A4C1E9A4F2B3C4D5E6F70")

    @patch("zentral.contrib.mdm.dep_client.DEPClient.send_request")
    def test_add_profile(self, send_request):
        profile = {"profile_name": "yolo", "devices": []}
        send_request.return_value = {"profile_uuid": "8ECF1F2E2B0A4C1E9A4F2B3C4D5E6F70"}
        response = build_client().add_profile(profile)
        self.assertEqual(response, {"profile_uuid": "8ECF1F2E2B0A4C1E9A4F2B3C4D5E6F70"})
        send_request.assert_called_once_with('profile', 'POST', json=profile)
