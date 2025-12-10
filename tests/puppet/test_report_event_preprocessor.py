from datetime import datetime
from unittest.mock import patch
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.puppet.models import Instance
from zentral.contrib.puppet.preprocessors import get_preprocessors
from .utils import build_report, build_self_signed_cert


class PuppetWebhookPreprocessorTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()
        cls.instance = Instance.objects.create(
            business_unit=cls.bu,
            url="https://{}.example.com".format(get_random_string(8)),
            ca_chain=build_self_signed_cert("CA")[0]
        )
        cls.instance.set_rbac_token(get_random_string(12))
        cls.token = get_random_string(12)
        cls.instance.set_report_processor_token(cls.token)
        cls.instance.save()
        cls.instance.refresh_from_db()
        cls.preprocessor = list(get_preprocessors())[0]

    # utils

    @classmethod
    def build_raw_event(cls, host, time):
        return {
            "request": {"ip": "127.0.0.1", "user_agent": "test"},
            "observer": cls.instance.observer_dict(),
            "puppet_instance": {"pk": cls.instance.pk, "version": cls.instance.version},
            "puppet_report": build_report(host, time)
        }

    # tests

    @patch("zentral.contrib.puppet.puppetdb_client.PuppetDBClient.get_machine_d")
    def test_raw_event(self, get_machine_d):
        host = get_random_string(12)
        serial_number = get_random_string(12)
        get_machine_d.return_value = {
            "source": {"module": "zentral.contrib.puppet",
                       "name": "puppet",
                       "config": {"url": self.instance.url}},
            "reference": host,
            "last_seen": datetime.utcnow(),
            "business_unit": self.bu.serialize(),
            "serial_number": serial_number,
            "system_info": {"computer_name": host}
        }
        raw_event = self.build_raw_event(host, '2022-02-16T17:37:47.337045569Z')
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertTrue(all(evt.metadata.machine_serial_number == serial_number for evt in events))
        self.assertEqual(len(events), 3)
        event0 = events[0]
        self.assertEqual(event0.metadata.event_type, "add_machine")
        event1 = events[1]
        self.assertEqual(event1.metadata.event_type, "inventory_heartbeat")
        event2 = events[2]
        self.assertEqual(event2.metadata.event_type, "puppet_report")
        self.assertEqual(event2.metadata.created_at, datetime(2022, 2, 16, 17, 37, 47, 337045))
        self.assertEqual(event2.payload['host'], host)
        self.assertEqual(event2.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event2.get_linked_objects_keys(), {"puppet_instance": [(self.instance.pk,)]})

    @patch("zentral.contrib.puppet.puppetdb_client.PuppetDBClient.get_machine_d")
    def test_raw_event_tz(self, get_machine_d):
        host = get_random_string(12)
        serial_number = get_random_string(12)
        get_machine_d.return_value = {
            "source": {"module": "zentral.contrib.puppet",
                       "name": "puppet",
                       "config": {"url": self.instance.url}},
            "reference": host,
            "last_seen": datetime.utcnow(),
            "business_unit": self.bu.serialize(),
            "serial_number": serial_number,
            "system_info": {"computer_name": host}
        }
        raw_event = self.build_raw_event(host, '2022-03-01T18:12:14.543069843+09:00')
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertTrue(all(evt.metadata.machine_serial_number == serial_number for evt in events))
        self.assertEqual(len(events), 3)
        event0 = events[0]
        self.assertEqual(event0.metadata.event_type, "add_machine")
        event1 = events[1]
        self.assertEqual(event1.metadata.event_type, "inventory_heartbeat")
        event2 = events[2]
        self.assertEqual(event2.metadata.event_type, "puppet_report")
        self.assertEqual(event2.metadata.created_at, datetime(2022, 3, 1, 9, 12, 14, 543069))
        self.assertEqual(event2.payload['host'], host)
        self.assertEqual(event2.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event2.get_linked_objects_keys(), {"puppet_instance": [(self.instance.pk,)]})
