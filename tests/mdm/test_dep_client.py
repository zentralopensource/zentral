from unittest.mock import Mock, patch

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
