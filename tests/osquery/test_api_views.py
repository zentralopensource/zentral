import json
from django.core.urlresolvers import reverse
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.osquery.conf import DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME, DEFAULT_ZENTRAL_INVENTORY_QUERY
from zentral.core.probes.models import ProbeSource
from zentral.utils.api_views import make_secret


DEFAULT_ZENTRAL_INVENTORY_QUERY_SNAPSHOT = [
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
     'hardware_model': 'MacBookPro5,1',
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


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class OsqueryAPIViewsTestCase(TestCase):
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

    def test_enroll_bad_enroll_secret_signature(self):
        response = self.post_as_json("enroll", {"enroll_secret": "INVALID ENROLL SECRET"})
        self.assertContains(response, "Bad secret signature", status_code=403)

    def test_enroll_enroll_secret_bad_module(self):
        secret = make_secret("zentral.inexisting.module")
        response = self.post_as_json("enroll", {"enroll_secret": secret})
        self.assertContains(response, "Invalid module", status_code=403)

    def test_enroll_not_machine_serial_number(self):
        secret = make_secret("zentral.contrib.osquery")
        response = self.post_as_json("enroll", {"enroll_secret": secret})
        self.assertEqual(response.status_code, 400)

    def test_enroll_ok(self):
        machine_serial_number = "210923091238731290"
        machine_test_qs = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                                         machine__serial_number=machine_serial_number)
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
        machine_serial_number = "210923091238731290"
        machine_test_qs = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                                         machine__serial_number=machine_serial_number)
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

    def enroll_machine(self, machine_serial_number):
        secret = "{}$SERIAL${}".format(make_secret("zentral.contrib.osquery"),
                                       machine_serial_number)
        response = self.post_as_json("enroll", {"enroll_secret": secret})
        json_response = response.json()
        return json_response["node_key"]

    def test_config_ok(self):
        node_key = self.enroll_machine("0123456789")
        response = self.post_as_json("config", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertIn("schedule", json_response)

    def test_distributed_read_405(self):
        response = self.client.get(reverse("osquery:distributed_read"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_distributed_read_default_inventory_query(self):
        node_key = self.enroll_machine("0123456789")
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response,
                         {"queries": {DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME: DEFAULT_ZENTRAL_INVENTORY_QUERY}})

    def post_default_inventory_query_snapshot(self, node_key):
        self.post_as_json("distributed_write",
                          {"node_key": node_key,
                           "queries": {
                               DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME: DEFAULT_ZENTRAL_INVENTORY_QUERY_SNAPSHOT,
                            }})

    def test_default_inventory_query_snapshot(self):
        node_key = self.enroll_machine("0123456789")
        self.post_default_inventory_query_snapshot(node_key)
        ms = MachineSnapshot.objects.current().get(machine__serial_number="0123456789")
        self.assertEqual(ms.os_version.build, DEFAULT_ZENTRAL_INVENTORY_QUERY_SNAPSHOT[0]["build"])

    def test_distributed_read_one_query_plus_default_inventory_query(self):
        node_key = self.enroll_machine("0123456789")
        # one distributed query probe
        dq = "select * from users;"
        probe_source = ProbeSource.objects.create(
            name="Shellac",
            status=ProbeSource.ACTIVE,
            model="OsqueryDistributedQueryProbe",
            body={"distributed_query": dq}
        )
        # distributed read
        response = self.post_as_json("distributed_read", {"node_key": node_key})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/json")
        json_response = response.json()
        self.assertEqual(json_response,
                         {
                            "queries": {
                                DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME: DEFAULT_ZENTRAL_INVENTORY_QUERY,
                                "q_{}".format(probe_source.pk): dq
                            }
                         })
        # post default inventory snapshot.
        self.post_default_inventory_query_snapshot(node_key)
        # 2nd distributed read empty (snapshot done and no other distributed queries available)
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
        node_key = self.enroll_machine("0123456789")
        # query
        probe_source = ProbeSource.objects.create(
            name="Shellac",
            status=ProbeSource.ACTIVE,
            model="OsqueryDistributedQueryProbe",
            body={"distributed_query": "select username from users;"}
        )
        response = self.post_as_json("distributed_write",
                                     {"node_key": node_key,
                                      "queries": {"q_{}".format(probe_source.pk): [{"username": "godzilla"}]}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})

    def test_log_405(self):
        response = self.client.get(reverse("osquery:log"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_log_default_inventory_query(self):
        node_key = self.enroll_machine("0123456789")
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
                "hardware_serial": "0123456789",
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
            }
        ]
        post_data = {
            "node_key": node_key,
            "log_type": "result",
            "data": [
                {"name": DEFAULT_ZENTRAL_INVENTORY_QUERY_NAME,
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

    def test_log_status(self):
        node_key = self.enroll_machine("0123456789")
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
        node_key = self.enroll_machine("0123456789")
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
        node_key = self.enroll_machine("0123456789")
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
