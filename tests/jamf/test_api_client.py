import copy
from unittest.mock import patch, Mock
from django.test import SimpleTestCase
from zentral.contrib.jamf.api_client import APIClient, APIClientError
from .data import computer_response, mobile_device_response


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

    # extension attributes → extra facts

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_extra_facts_ok(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "YOLO FOMO",
                "type": "String",
                "multi_value": True,
                "value": ["1", "2"],
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            inventory_extension_attributes=["BOOTSTRAP", "Computer Sleep", "YOLO FOMO"]  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(
            machine_d["extra_facts"],
            {"Bootstrap": "NO", "Computer Sleep": "1", "YOLO FOMO": ["1", "2"]}
        )

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_extra_facts_ea_missing_name(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                # Missing name
                "type": "String",
                "multi_value": False,
                "value": "YOLO FOMO",
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            inventory_extension_attributes=["YOLO FOMO"]
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertNotIn("extra_facts", machine_d)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_extra_facts_list_too_long(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "YOLO FOMO",
                "type": "String",
                "multi_value": True,
                "value": ["1" for _ in range(101)],
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            inventory_extension_attributes=["YOLO FOMO"]
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertNotIn("extra_facts", machine_d)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_extra_facts_str_too_long(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "YOLO FOMO 1",
                "type": "String",
                "multi_value": True,
                "value": ["1" * 1001],
            },
            {
                "id": 79,
                "name": "YOLO FOMO 2",
                "type": "String",
                "multi_value": False,
                "value": 1001 * "1",
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            inventory_extension_attributes=["YOLO FOMO 1", "YOLO FOMO 2"]
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertNotIn("extra_facts", machine_d)

    # extension attributes → principal user

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_principal_user_ok(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "UID",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe",
            },
            {
                "id": 79,
                "name": "Principal Name",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe@example.com",
            },
            {
                "id": 80,
                "name": "User full name",
                "type": "String",
                "multi_value": False,
                "value": "Jane Doe",
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            principal_user_uid_extension_attribute="UID",
            principal_user_pn_extension_attribute="principal Name",  # case insensitive
            principal_user_dn_extension_attribute="user full name",  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(
            machine_d["principal_user"],
            {"source": {"properties": {'config': {'host': 'host', 'path': '/JSSResource', 'port': 443},
                                       'module': 'zentral.contrib.jamf',
                                       'name': 'jamf'},
                        "type": "INVENTORY"},
             "unique_id": "jane.doe",
             "principal_name": "jane.doe@example.com",
             "display_name": "Jane Doe"}
        )

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_principal_user_same_ea_ok(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "Email",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe@example.com",
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            principal_user_uid_extension_attribute="Email",  # case insensitive
            principal_user_pn_extension_attribute="email",  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(
            machine_d["principal_user"],
            {"source": {"properties": {'config': {'host': 'host', 'path': '/JSSResource', 'port': 443},
                                       'module': 'zentral.contrib.jamf',
                                       'name': 'jamf'},
                        "type": "INVENTORY"},
             "unique_id": "jane.doe@example.com",
             "principal_name": "jane.doe@example.com"}
        )

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_principal_user_wrong_values(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "UID",
                "type": "String",
                "multi_value": False,
                "value": 1000 * "jane.doe",
            },
            {
                "id": 79,
                "name": "Principal Name",
                "type": "String",
                "multi_value": False,
                "value": "",
            },
            {
                "id": 80,
                "name": "User full name",
                "type": "String",
                "multi_value": False,
                "value": 11,
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            principal_user_uid_extension_attribute="UID",
            principal_user_pn_extension_attribute="principal Name",  # case insensitive
            principal_user_dn_extension_attribute="user full name",  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertNotIn("principal_user", machine_d)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_principal_user_missing_ea_name(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 78,
                "name": "UID",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe",
            },
            {
                "id": 79,
                "name": "Principal Name",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe@example.com",
            },
            {
                "id": 80,
                "type": "String",
                "multi_value": False,
                "value": 11,
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            principal_user_uid_extension_attribute="UID",
            principal_user_pn_extension_attribute="principal Name",  # case insensitive
            principal_user_dn_extension_attribute="user full name",  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(
            machine_d["principal_user"],
            {"source": {"properties": {'config': {'host': 'host', 'path': '/JSSResource', 'port': 443},
                                       'module': 'zentral.contrib.jamf',
                                       'name': 'jamf'},
                        "type": "INVENTORY"},
             "unique_id": "jane.doe",
             "principal_name": "jane.doe@example.com"}
        )

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_principal_user_missing_uid(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["extension_attributes"].extend([
            {
                "id": 79,
                "name": "Principal Name",
                "type": "String",
                "multi_value": False,
                "value": "jane.doe@example.com",
            },
            {
                "id": 80,
                "name": "User full name",
                "type": "String",
                "multi_value": False,
                "value": "Jane Doe",
            }
        ])
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient(
            "host", 443, "/JSSResource", "user", "pwd", "sec",
            principal_user_uid_extension_attribute="UID",
            principal_user_pn_extension_attribute="principal Name",  # case insensitive
            principal_user_dn_extension_attribute="user full name",  # case insensitive
        )
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertNotIn("principal_user", machine_d)

    # OS version patch

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_patch(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["hardware"]["os_version"] = "12.5.1"  # patch
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(machine_d["os_version"]["major"], 12)
        self.assertEqual(machine_d["os_version"]["minor"], 5)
        self.assertEqual(machine_d["os_version"]["patch"], 1)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_computer_patch_zero(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        computer = copy.deepcopy(computer_response)
        computer["hardware"]["os_version"] = "12.5"  # no patch number
        response.json.return_value = {"computer": computer}
        session_get.return_value = response
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        machine_d = api_client.get_machine_d("computer", 1)
        self.assertEqual(machine_d["os_version"]["major"], 12)
        self.assertEqual(machine_d["os_version"]["minor"], 5)
        self.assertEqual(machine_d["os_version"]["patch"], 0)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_mobile_device_patch(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        mobile_device = copy.deepcopy(mobile_device_response)
        mobile_device["general"]["os_version"] = "15.5.2"  # patch
        response.json.return_value = {"mobile_device": mobile_device}
        session_get.return_value = response
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        machine_d = api_client.get_machine_d("mobile_device", 2)
        self.assertEqual(machine_d["os_version"]["major"], 15)
        self.assertEqual(machine_d["os_version"]["minor"], 5)
        self.assertEqual(machine_d["os_version"]["patch"], 2)

    @patch("zentral.contrib.jamf.api_client.requests.Session.get")
    def test_mobile_device_patch_zero(self, session_get):
        response = Mock()
        response.status_code = 200
        response.json = Mock()
        mobile_device = copy.deepcopy(mobile_device_response)
        mobile_device["general"]["os_version"] = "15.5"  # no patch number
        response.json.return_value = {"mobile_device": mobile_device}
        session_get.return_value = response
        api_client = APIClient("host", 443, "/JSSResource", "user", "pwd", "sec")
        machine_d = api_client.get_machine_d("mobile_device", 2)
        self.assertEqual(machine_d["os_version"]["major"], 15)
        self.assertEqual(machine_d["os_version"]["minor"], 5)
        self.assertEqual(machine_d["os_version"]["patch"], 0)
