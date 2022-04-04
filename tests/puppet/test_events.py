from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.puppet.models import Instance
from zentral.contrib.puppet.puppetdb_client import PuppetDBClient
from zentral.core.events import event_cls_from_type
from .utils import build_self_signed_cert


class PuppetEventsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()
        cls.instance = Instance.objects.create(
            business_unit=cls.bu,
            url="https://{}.example.com".format(get_random_string(8)),
            ca_chain=build_self_signed_cert("CA")[0],
            report_heartbeat_timeout=703
        )
        cls.instance.set_rbac_token(get_random_string(12))
        cls.instance.set_report_processor_token(get_random_string(12))
        cls.instance.save()

    def commit_minimal_ms_tree(self):
        serial_number = get_random_string(12)
        client = PuppetDBClient.from_instance(self.instance)
        ms_tree = {"source": client.get_source_d(),
                   "reference": 123,
                   "serial_number": serial_number}
        commit_machine_snapshot_and_trigger_events(ms_tree)
        return serial_number

    def test_report_heartbeat_timeout_unknown_machine(self):
        event_cls = event_cls_from_type("puppet_report")
        self.assertIsNone(event_cls.get_machine_heartbeat_timeout(get_random_string(12)))

    def test_report_heartbeat_timeout(self):
        serial_number = self.commit_minimal_ms_tree()
        event_cls = event_cls_from_type("puppet_report")
        self.assertEqual(event_cls.get_machine_heartbeat_timeout(serial_number), 703)
