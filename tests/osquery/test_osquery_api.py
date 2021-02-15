from datetime import datetime
import json
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineSnapshot, MetaBusinessUnit
from zentral.contrib.osquery.conf import INVENTORY_QUERY_NAME
from zentral.contrib.osquery.models import (Configuration,
                                            DistributedQuery, DistributedQueryMachine, DistributedQueryResult,
                                            EnrolledMachine, Enrollment)


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
     'hardware_model': 'MacBookPro5,1 \u0000',  # extra space and NULL must be removed by osquery module
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
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=enrollment_secret)
        enrollment_secret2 = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment2 = Enrollment.objects.create(configuration=cls.configuration,
                                                    secret=enrollment_secret2)

    # utiliy methods

    def post_as_json(self, url_name, data):
        return self.client.post(reverse("osquery:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    def force_enrolled_machine(self):
        return EnrolledMachine.objects.create(
            enrollment=self.enrollment,
            serial_number=get_random_string(),
            node_key=get_random_string()
        )

    def post_default_inventory_query_snapshot(self, node_key, with_app=False, with_azure_ad=False):
        snapshot = list(INVENTORY_QUERY_SNAPSHOT)
        if with_app:
            snapshot.append(OSX_APP_INSTANCE)
        if with_azure_ad:
            snapshot.extend(AZURE_AD_INFO_TUPLES)
        return self.post_as_json(
            "log",
            {"node_key": node_key,
             "log_type": "result",
             "data": [{
                 'action': 'snapshot',
                 "name": INVENTORY_QUERY_NAME,
                 "snapshot": snapshot,
                 'unixTime': '1480605737',
             }]}
        )

    # enrollment

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
        self.assertContains(response, "Wrong enrollment secret", status_code=403)

    def test_enroll_no_serial_number(self):
        response = self.post_as_json("enroll", {"enroll_secret": self.enrollment.secret.secret})
        self.assertEqual(response.status_code, 400)

    def test_enroll_ok(self):
        serial_number = get_random_string()
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": self.enrollment.secret.secret,
             "host_details": {"system_info": {"hardware_serial": serial_number}}}
        )
        self.assertEqual(response.status_code, 200)
        em = EnrolledMachine.objects.get(enrollment=self.enrollment, serial_number=serial_number)
        self.assertEqual(response.json(), {"node_key": em.node_key})
        ms = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                            serial_number=serial_number)
        self.assertEqual(ms.first().reference, em.node_key)

    def test_enroll_with_host_identifier_ok(self):
        serial_number = get_random_string()
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": self.enrollment.secret.secret,
             "host_identifier": serial_number}
        )
        self.assertEqual(response.status_code, 200)
        em = EnrolledMachine.objects.get(enrollment=self.enrollment, serial_number=serial_number)
        self.assertEqual(response.json(), {"node_key": em.node_key})
        ms = MachineSnapshot.objects.filter(source__module="zentral.contrib.osquery",
                                            serial_number=serial_number)
        self.assertEqual(ms.first().reference, em.node_key)

    def test_re_enroll_same_enrollment(self):
        old_em = self.force_enrolled_machine()
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": self.enrollment.secret.secret,
             "host_details": {"system_info": {"hardware_serial": old_em.serial_number}}}
        )
        self.assertEqual(response.status_code, 200)
        em = EnrolledMachine.objects.get(enrollment=self.enrollment, serial_number=old_em.serial_number)
        self.assertEqual(response.json(), {"node_key": em.node_key})
        self.assertEqual(old_em, em)

    def test_re_enroll_different_enrollment(self):
        old_em = self.force_enrolled_machine()
        response = self.post_as_json(
            "enroll",
            {"enroll_secret": self.enrollment2.secret.secret,
             "host_details": {"system_info": {"hardware_serial": old_em.serial_number}}}
        )
        self.assertEqual(response.status_code, 200)
        em = EnrolledMachine.objects.get(enrollment=self.enrollment2, serial_number=old_em.serial_number)
        self.assertEqual(response.json(), {"node_key": em.node_key})
        self.assertEqual(EnrolledMachine.objects.filter(serial_number=old_em.serial_number).count(), 1)

    # config

    def test_config_405(self):
        response = self.client.get(reverse("osquery:enroll"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_config_missing_node_key(self):
        response = self.post_as_json("config", {"godzilla": "ffm"})
        self.assertEqual(response.status_code, 400)

    def test_config_wrong_node_key(self):
        response = self.post_as_json("config", {"node_key": "godzilla"})
        self.assertContains(response, "Wrong node_key", status_code=403)

    def test_config_ok(self):
        em = self.force_enrolled_machine()
        response = self.post_as_json("config", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertIn("schedule", json_response)
        schedule = json_response["schedule"]
        self.assertIn(INVENTORY_QUERY_NAME, schedule)

    def test_osx_app_instance_schedule(self):
        em = self.force_enrolled_machine()
        self.post_default_inventory_query_snapshot(em.node_key)
        response = self.post_as_json("config", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertIn("schedule", json_response)
        schedule = json_response["schedule"]
        self.assertIn(INVENTORY_QUERY_NAME, schedule)
        self.assertNotIn(" 'apps' ", schedule[INVENTORY_QUERY_NAME]["query"])
        self.configuration.inventory_apps = True
        self.configuration.save()
        response = self.post_as_json("config", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertIn("schedule", json_response)
        schedule = json_response["schedule"]
        self.assertIn(INVENTORY_QUERY_NAME, schedule)
        self.assertIn(" 'apps' ", schedule[INVENTORY_QUERY_NAME]["query"])

    # distributed queries

    def test_distributed_read_405(self):
        response = self.client.get(reverse("osquery:distributed_read"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_distributed_read_missing_node_key(self):
        response = self.post_as_json("distributed_read", {"godzilla": "ffm"})
        self.assertEqual(response.status_code, 400)

    def test_distributed_read_wrong_node_key(self):
        response = self.post_as_json("distributed_read", {"node_key": "godzilla"})
        self.assertContains(response, "Wrong node_key", status_code=403)

    def test_distributed_read_empty(self):
        em = self.force_enrolled_machine()
        response = self.post_as_json("distributed_read", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"queries": {}})

    def test_distributed_read_one_query(self):
        em = self.force_enrolled_machine()
        # one distributed query probe
        dq = DistributedQuery.objects.create(sql="select username from users;",
                                             valid_from=datetime.utcnow(),
                                             query_version=1)
        response = self.post_as_json("distributed_read", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        dqm_qs = DistributedQueryMachine.objects.filter(distributed_query=dq, serial_number=em.serial_number)
        self.assertEqual(dqm_qs.count(), 1)
        self.assertEqual(dqm_qs.first().status, None)
        json_response = response.json()
        self.assertEqual(json_response, {"queries": {str(dqm_qs.first().pk): dq.sql}})
        # 2nd distributed read still has the inventory query
        response = self.post_as_json("distributed_read", {"node_key": em.node_key})
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {"queries": {}})
        self.assertEqual(dqm_qs.count(), 1)
        self.assertEqual(dqm_qs.first().status, None)

    def test_distributed_write_405(self):
        response = self.client.get(reverse("osquery:distributed_write"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_distributed_write_missing_node_key(self):
        response = self.post_as_json("distributed_write", {"godzilla": "ffm"})
        self.assertEqual(response.status_code, 400)

    def test_distributed_write_wrong_node_key(self):
        response = self.post_as_json("distributed_write", {"node_key": "godzilla"})
        self.assertContains(response, "Wrong node_key", status_code=403)

    def test_distributed_write_ok(self):
        em = self.force_enrolled_machine()
        dq = DistributedQuery.objects.create(sql="select username from users;",
                                             valid_from=datetime.utcnow(),
                                             query_version=1)
        dqm = DistributedQueryMachine.objects.create(distributed_query=dq, serial_number=em.serial_number)
        response = self.post_as_json("distributed_write",
                                     {"node_key": em.node_key,
                                      "queries": {str(dqm.pk): [{"username": "godzilla"}]},
                                      "statuses": {str(dqm.pk): 0}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {})
        dqm.refresh_from_db()
        self.assertEqual(dqm.status, 0)
        dqr_qs = DistributedQueryResult.objects.filter(distributed_query=dq, serial_number=em.serial_number)
        self.assertEqual(dqr_qs.count(), 1)
        self.assertEqual(dqr_qs.first().row, {"username": "godzilla"})

    # log

    def test_log_405(self):
        response = self.client.get(reverse("osquery:log"))
        self.assertEqual(response.status_code, 405)
        self.assertCountEqual(["POST", "OPTIONS"], (m.strip() for m in response["Allow"].split(",")))

    def test_log_missing_node_key(self):
        response = self.post_as_json("log", {"godzilla": "ffm"})
        self.assertEqual(response.status_code, 400)

    def test_log_wrong_node_key(self):
        response = self.post_as_json("log", {"node_key": "godzilla"})
        self.assertContains(response, "Wrong node_key", status_code=403)

    def test_log_default_inventory_query(self):
        em = self.force_enrolled_machine()
        response = self.post_default_inventory_query_snapshot(em.node_key, with_app=True)
        self.assertEqual(response.status_code, 200)
        json_response = response.json()
        self.assertEqual(json_response, {})
        ms = MachineSnapshot.objects.current().get(serial_number=em.serial_number, reference=em.node_key)
        self.assertEqual(ms.os_version.build, INVENTORY_QUERY_SNAPSHOT[0]["build"])
        self.assertEqual(ms.system_info.hardware_model, INVENTORY_QUERY_SNAPSHOT[1]["hardware_model"].strip(" \u0000"))
        self.assertEqual(list(ms.osx_app_instances.values_list("app__bundle_name", flat=True)),
                         [OSX_APP_INSTANCE["bundle_name"]])

    def test_log_status(self):
        em = self.force_enrolled_machine()
        post_data = {
            "node_key": em.node_key,
            "log_type": "status",
            "data": [
                {'filename': 'scheduler.cpp',
                 'line': '63',
                 'message': 'Executing scheduled query: macos-attacks-query-pack_604dc4d3: '
                            "select * from startup_items where path like '%iWorkServices%';",
                 'severity': '0',
                 'version': '2.1.2',
                 'unixTime': '1480605737'}
            ]
        }
        response = self.post_as_json("log", post_data)
        json_response = response.json()
        self.assertEqual(json_response, {})

    def test_log_added_result(self):
        em = self.force_enrolled_machine()
        post_data = {
            "node_key": em.node_key,
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
        json_response = response.json()
        self.assertEqual(json_response, {})

    def test_log_snapshot_result(self):
        em = self.force_enrolled_machine()
        post_data = {
            "node_key": em.node_key,
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
        json_response = response.json()
        self.assertEqual(json_response, {})
