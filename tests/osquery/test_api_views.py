import json
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineSnapshot, MetaBusinessUnit
from zentral.contrib.osquery.conf import (INVENTORY_QUERY_NAME,
                                          INVENTORY_DISTRIBUTED_QUERY_PREFIX)
from zentral.contrib.osquery.models import Configuration, Enrollment
from zentral.core.probes.conf import all_probes
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import make_secret


INVENTORY_QUERY_SNAPSHOT = [
    {'build': '15D21',
     'major': '10',
     'minor': '11',
     'name': 'Mac OS X',
     'patch': '3',
     'table_name': 'os_version'},
    {'computer_name': 'godzilla',
     'cpu_brand': 'Intel(R) Core(TM)2 Duo CPU T9600 @2.80GHz',
     'cpu_logical_cores': '2',
     'cpu_physical_cores': '2',
     'cpu_subtype': 'Intel 80486',
     'cpu_type': 'i486',
     'hardware_model': 'MacBookPro5,1 ',  # extra space must be removed by osquery module
     'hardware_serial': '0123456789',
     'hostname': 'godzilla.box',
     'physical_memory': '8589934592',
     'table_name': 'system_info'},
    {'address': '192.168.1.123',
     'broadcast': '192.168.1.255',
     'interface': 'en1',
     'mac': '00:23:ac:a8:49:a9',
     'mask': '255.255.255.0',
     'table_name': 'network_interface'}
]

OSX_APP_INSTANCE = {
    "bundle_id": "com.agilebits.onepassword4-updater",
    "bundle_name": "1Password Updater",
    "bundle_path": "/Applications/1Password 6.app/Contents/Helpers/1Password Updater.app",
    "bundle_version": "652003",
    "bundle_version_str": "6.5.2",
    "table_name": "apps"
}

AZURE_AD_INFO_TUPLES = [
    {"common_name": "d14a06da-2547-4c80-9c5a-4851d1e4c7b2",
     "not_valid_before": "1556232938",
     "table_name": "azure_ad_certificate"},
    {"username": "jean",
     "key": "aadUniqueId",
     "value": "fc0e524e-9b87-4f63-a318-02727dc7983e",
     "table_name": "azure_ad_user_info"},
    {"username": "jean",
     "key": "aadUserId",
     "value": "jean@example.com",
     "table_name": "azure_ad_user_info"},
    {"username": "jean",
     "key": "version",
     "value": "1.1",
     "table_name": "azure_ad_user_info"},
    {"username": "jean",
     "key": "aadAuthorityUrl",
     "value": "https://login.microsoftonline.com/common",
     "table_name": "azure_ad_user_info"},
]


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsqueryAPIViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256))
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=cls.enrollment_secret)

    def post_as_json(self, url_name, data):
        return self.client.post(reverse("osquery:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def test_enroll_405(self):
        response = self.client.get(reverse("osquery:enroll"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_enroll_bad_json(self):
        response = self.client.post(reverse("osquery:enroll"))
        self.assertEqual(response.status_code, 400)
        response = self.client.post(reverse("osquery:enroll"),
                                    data="lkjadslkjdsalkdjas",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_enroll_missing_json_keys(self):
        response = self.post_as_json("enroll", {"no_enroll_secret_key": True})
        self.assertEqual(response.status_code, 400)

    def test_enroll_bad_secret(self):
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": "INVALID ENROLL SECRET",
             "host_details": {"system_info": {"hardware_serial": get_random_string(32)}}}
        )
        self.assertContains(response, "Unknown enrolled machine", status_code=403)

    def test_enroll_enroll_secret_bad_module_old_way(self):
        # TODO: deprecate and remove
        secret = "{}$SERIAL${}".format(make_secret("zentral.inexisting.module"), get_random_string(32))
        response = self.post_as_json("enroll", {"enroll_secret": secret})
        self.assertContains(response, "Invalid module", status_code=403)

    def test_enroll_not_machine_serial_number(self):
        response = self.post_as_json("enroll", {"enroll_secret": self.enrollment.secret.secret})
        self.assertContains(response, "No serial number", status_code=403)

    def test_enroll_ok_old_way(self):
        # TODO: deprecate and remove
        machine_serial_number = get_random_string(32)
        machine_test_qs = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                                         serial_number=machine_serial_number)
        # no machine
        self.assertEqual(machine_test_qs.count(), 0)
        # enroll machine
        secret = "{}$SERIAL${}".format(make_secret("zentral.contrib.osquery"),
                                       machine_serial_number)
        response = self.post_as_json("enroll", {"enroll_secret": secret})
        json_response = response.json()
        self.assertCountEqual(["node_key"], json_response.keys())
        self.assertEqual(machine_test_qs.count(), 1)
        machine = machine_test_qs.all()[0]
        self.assertEqual(machine.reference, json_response["node_key"])

    def test_enroll_with_host_identifier_ok(self):
        machine_serial_number = get_random_string(32)
        machine_test_qs = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                                         serial_number=machine_serial_number)
        # no machine
        self.assertEqual(machine_test_qs.count(), 0)
        # enroll machine
        secret = "{}$SERIAL${}".format(make_secret("zentral.contrib.osquery"),
                                       machine_serial_number)
        response = self.post_as_json("enroll", {"enroll_secret": secret,
                                                "host_identifier": "godzilla"})
        json_response = response.json()
        self.assertCountEqual(["node_key"], json_response.keys())
        self.assertEqual(machine_test_qs.count(), 1)
        machine = machine_test_qs.all()[0]
        self.assertEqual(machine.reference, json_response["node_key"])
        self.assertEqual(machine.system_info.computer_name, "godzilla")

    def test_re_enroll(self):
        machine_serial_number = get_random_string(32)
        # enroll machine
        secret = "{}$SERIAL${}".format(make_secret("zentral.contrib.osquery"),
                                       machine_serial_number)
        response = self.post_as_json("enroll", {"enroll_secret": secret,
                                                "host_identifier": "godzilla"})
        json_response = response.json()
        node_key = json_response["node_key"]
        # re-enroll machine
        response = self.post_as_json("enroll", {"enroll_secret": secret,
                                                "host_identifier": "godzilla"})
        json_response = response.json()
        self.assertEqual(json_response["node_key"], node_key)

    def test_config_405(self):
        response = self.client.get(reverse("osquery:enroll"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_config_missing_node_key(self):
        response = self.post_as_json("config", {"godzilla": "ffm"})
        self.assertContains(response, "Missing node_key", status_code=403)

    def test_config_wrong_node_key(self):
        response = self.post_as_json("config", {"node_key": "godzilla"})
        self.assertContains(response, "Wrong node_key", status_code=403)

    def enroll_machine(self):
        machine_serial_number = get_random_string(64)
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": self.enrollment.secret.secret,
             "host_details": {"system_info": {"hardware_serial": machine_serial_number}}}
        )
        self.assertEqual(response.status_code, 200)
        return machine_serial_number, response.json()["node_key"]

    def test_config_ok(self):
        _, node_key = self.enroll_machine()
        response = self.post_as_json("config", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertIn("schedule", json_response)
        schedule = json_response["schedule"]
        self.assertIn(INVENTORY_QUERY_NAME, schedule)

    def test_osx_app_instance_schedule(self):
        _, node_key = self.enroll_machine()
        self.post_default_inventory_query_snapshot(node_key)
        # machine platform = MACOS now
        response = self.post_as_json("config", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertIn("schedule", json_response)
        schedule = json_response["schedule"]
        self.assertIn(INVENTORY_QUERY_NAME, schedule)
        self.assertIn(" 'apps' ", schedule[INVENTORY_QUERY_NAME]["query"])

    def test_distributed_read_405(self):
        response = self.client.get(reverse("osquery:distributed_read"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_distributed_read_default_inventory_query(self):
        _, node_key = self.enroll_machine()
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        query_names = ["{}{}".format(INVENTORY_DISTRIBUTED_QUERY_PREFIX, t)
                       for t in ("os_version", "system_info", "uptime", "network_interface")]
        self.assertCountEqual(json_response["queries"], query_names)

    def post_default_inventory_query_snapshot(self, node_key, with_app=False, with_azure_ad=False):
        snapshot = list(INVENTORY_QUERY_SNAPSHOT)
        if with_app:
            snapshot.append(OSX_APP_INSTANCE)
        if with_azure_ad:
            snapshot.extend(AZURE_AD_INFO_TUPLES)
        self.post_as_json("distributed_write",
                          {"node_key": node_key,
                           "queries": {"{}{}".format(INVENTORY_DISTRIBUTED_QUERY_PREFIX, i["table_name"]): [i]
                                       for i in snapshot}
                           })

    def test_default_inventory_query_snapshot(self):
        machine_serial_number, node_key = self.enroll_machine()
        self.post_default_inventory_query_snapshot(node_key)
        ms = MachineSnapshot.objects.current().get(serial_number=machine_serial_number)
        self.assertEqual(ms.os_version.build, INVENTORY_QUERY_SNAPSHOT[0]["build"])
        self.assertEqual(ms.system_info.hardware_model, INVENTORY_QUERY_SNAPSHOT[1]["hardware_model"].strip())

    def test_distributed_read_one_query_plus_default_inventory_query(self):
        _, node_key = self.enroll_machine()
        # one distributed query probe
        dq = "select * from users;"
        probe_source = ProbeSource.objects.create(
            name="Shellac",
            status=ProbeSource.ACTIVE,
            model="OsqueryDistributedQueryProbe",
            body={"distributed_query": dq}
        )
        dq_name = "dq_{}".format(probe_source.pk)
        # simulate an all_probes sync
        all_probes.clear()
        # distributed read
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        query_names = ["{}{}".format(INVENTORY_DISTRIBUTED_QUERY_PREFIX, t)
                       for t in ("os_version", "system_info", "uptime", "network_interface")]
        query_names.append(dq_name)
        self.assertCountEqual(json_response["queries"], query_names)
        self.assertEqual(json_response["queries"][dq_name], dq)
        # post default inventory snapshot.
        self.post_default_inventory_query_snapshot(node_key)
        # 2nd distributed read still has the inventory query
        # but with the apps and azure ad info queries, now that we know
        # what kind of machine it is
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        query_names = ["{}{}".format(INVENTORY_DISTRIBUTED_QUERY_PREFIX, t)
                       for t in ("os_version", "system_info", "uptime", "network_interface",
                                 "apps", "company_portal", "certificates")]
        self.assertCountEqual(json_response["queries"], query_names)
        # post default inventory snapshot with one app, and the azure ad info
        self.post_default_inventory_query_snapshot(node_key, with_app=True, with_azure_ad=True)
        # 3rd distributed read empty (2 snapshots done and no other distributed queries available)
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response, {"queries": {}})

    def test_distributed_write_405(self):
        response = self.client.get(reverse("osquery:distributed_write"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_distributed_write(self):
        _, node_key = self.enroll_machine()
        # query
        probe_source = ProbeSource.objects.create(
            name="Shellac",
            status=ProbeSource.ACTIVE,
            model="OsqueryDistributedQueryProbe",
            body={"distributed_query": "select username from users;"}
        )
        response = self.post_as_json("distributed_write",
                                     {"node_key": node_key,
                                      "queries": {"dq_{}".format(probe_source.pk): [{"username": "godzilla"}]}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    def test_log_405(self):
        response = self.client.get(reverse("osquery:log"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_log_default_inventory_query(self):
        machine_serial_number, node_key = self.enroll_machine()
        snapshot = [
            {
                "build": "15G1108",
                "major": "10",
                "minor": "11",
                "name": "Mac OS X",
                "patch": "6",
                "table_name": "os_version"
            },
            {
                "computer_name": "godzilla",
                "cpu_brand": "Intel(R) Core(TM) i7-4578U CPU @ 3.00GHz",
                "cpu_logical_cores": "4",
                "cpu_physical_cores": "2",
                "cpu_subtype": "Intel x86-64h Haswell",
                "cpu_type": "x86_64h",
                "hardware_model": "MacBookPro11,1",
                "hardware_serial": machine_serial_number,
                "hostname": "godzilla",
                "physical_memory": "17179869184",
                "table_name": "system_info"
            },
            {
                "address": "192.168.1.17",
                "broadcast": "192.168.1.255",
                "interface": "en3",
                "mac": "38:c9:87:21:b1:32",
                "mask": "255.255.255.0",
                "table_name": "network_interface"
            },
            OSX_APP_INSTANCE,
        ]
        post_data = {
            "node_key": node_key,
            "log_type": "result",
            "data": [
                {"name": INVENTORY_QUERY_NAME,
                 "unixTime": '1480605737',
                 "snapshot": snapshot}
            ]
        }
        # no machine named godzilla
        self.assertEqual(MachineSnapshot.objects.filter(reference=node_key,
                                                        system_info__computer_name="godzilla").count(), 0)
        # post new snapshot
        response = self.post_as_json("log", post_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response, {})
        # new machine snapshot, one of them is godzilla
        self.assertEqual(MachineSnapshot.objects.filter(reference=node_key).count(), 2)
        self.assertEqual(MachineSnapshot.objects.filter(reference=node_key,
                                                        system_info__computer_name="godzilla").count(), 1)
        self.assertEqual(MachineSnapshot.objects.filter(
            reference=node_key,
            osx_app_instances__app__bundle_name="1Password Updater").count(), 1)

    def test_log_status(self):
        _, node_key = self.enroll_machine()
        post_data = {
            "node_key": node_key,
            "log_type": "status",
            "data": [
                {'filename': 'scheduler.cpp',
                 'line': '63',
                 'message': 'Executing scheduled query: macos-attacks-query-pack_604dc4d3: '
                            "select * from startup_items where path like '%iWorkServices%';",
                 'severity': '0',
                 'version': '2.1.2'}
            ]
        }
        response = self.post_as_json("log", post_data)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response, {})

    def test_log_event_format_result(self):
        _, node_key = self.enroll_machine()
        post_data = {
            "node_key": node_key,
            "log_type": "result",
            "data": [
                {'name': 'godzilla_kommt-343hdwkl',
                 'action': 'added',
                 'hostIdentifier': 'godzilla.local',
                 'columns': {'name': 'Dropbox', 'pid': '1234', 'port': '17500'},
                 'unixTime': '1480605737'}
            ]
        }
        response = self.post_as_json("log", post_data)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response, {})

    def test_log_snapshot_format_result(self):
        _, node_key = self.enroll_machine()
        post_data = {
            "node_key": node_key,
            "log_type": "result",
            "data": [
                {'name': 'godzilla_kommt-343hdwkl',
                 'action': 'snapshot',
                 'hostIdentifier': 'godzilla.local',
                 "snapshot": [
                     {
                         "parent": "0",
                         "path": "/sbin/launchd",
                         "pid": "1"
                     },
                     {
                         "parent": "1",
                         "path": "/usr/sbin/syslogd",
                         "pid": "51"
                     }
                 ],
                 'unixTime': '1480605737'}
            ]
        }
        response = self.post_as_json("log", post_data)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response, {})
