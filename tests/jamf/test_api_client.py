from django.test import SimpleTestCase
from zentral.contrib.jamf.api_client import APIClient, APIClientError


class JamfAPIClientTestCase(SimpleTestCase):
    def test_base_url(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(api_client.base_url, "https://host:443")

    def test_source_d(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client.get_source_d(),
            {"module": "zentral.contrib.jamf",
             "name": "jamf",
             "config": {
                 "host": "host",
                 "path": "/JSSResource",
                 "port": 443,
             }}
        )

    def test_source_repr(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(api_client.source_repr, "host")

    def test_machine_links_from_id(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client._machine_links_from_id("computer", 123),
            [{"anchor_text": "Inventory",
              "url": "https://host:443/computers.html?id=123&o=r"},
             {"anchor_text": "Management",
              "url": "https://host:443/computers.html?id=123&o=r&v=management"}]
        )

    def test_machine_reference(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client.machine_reference("computer", 123),
            "computer,123"
        )

    def test_smart_group_reference(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client.group_reference("computer", 123, True),
            "computer,smart,123"
        )

    def test_static_group_reference(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client.group_reference("computer", 123, False),
            "computer,static,123"
        )

    def test_smart_computer_group_links(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client._group_links("computer", 123, True),
            [{"anchor_text": "Group",
              "url": "https://host:443/smartComputerGroups.html?id=123&o=r&nav=c"}]
        )

    def test_static_mobile_device_group_links(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        self.assertEqual(
            api_client._group_links("mobile_device", 123, False),
            [{"anchor_text": "Group",
              "url": "https://host:443/staticMobileDeviceGroups.html?id=123&o=r&nav=c"}]
        )

    def test_group_machine_references_unknown_device_type(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        with self.assertRaises(APIClientError) as cm:
            list(api_client.get_group_machine_references("yolo", 123))
        self.assertEqual(cm.exception.args[0], "Unknown device type: yolo")

    def test_get_machine_d_unknown_device_type(self):
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        with self.assertRaises(APIClientError) as cm:
            api_client.get_machine_d("yolo", 123)
        self.assertEqual(cm.exception.args[0], "Unknown device type: yolo")
