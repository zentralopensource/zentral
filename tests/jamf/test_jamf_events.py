from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.jamf.api_client import APIClient
from zentral.contrib.jamf.models import JamfInstance
from zentral.core.events import event_cls_from_type


class JamfEventsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.jamf_instance = JamfInstance.objects.create(
            host="{}.example.com".format(get_random_string(12)),
            port=443,
            path="/JSSResource",
            user=get_random_string(12),
            checkin_heartbeat_timeout=703,
            inventory_completed_heartbeat_timeout=7203,
        )
        cls.jamf_instance.set_password(get_random_string(12))
        super(JamfInstance, cls.jamf_instance).save()

    def commit_minimal_ms_tree(self):
        serial_number = get_random_string(12)
        api_client = APIClient(**self.jamf_instance.serialize(decrypt_password=True))
        ms_tree = {"source": api_client.get_source_d(),
                   "reference": 123,
                   "serial_number": serial_number}
        commit_machine_snapshot_and_trigger_events(ms_tree)
        return serial_number

    def test_checkin_heartbeat_timeout_unknown_machine(self):
        event_cls = event_cls_from_type("jamf_computer_checkin")
        self.assertIsNone(event_cls.get_machine_heartbeat_timeout(get_random_string(12)))

    def test_inventory_completed_heartbeat_timeout_unknown_machine(self):
        event_cls = event_cls_from_type("jamf_computer_inventory_completed")
        self.assertIsNone(event_cls.get_machine_heartbeat_timeout(get_random_string(12)))

    def test_checkin_heartbeat_timeout(self):
        serial_number = self.commit_minimal_ms_tree()
        event_cls = event_cls_from_type("jamf_computer_checkin")
        self.assertEqual(event_cls.get_machine_heartbeat_timeout(serial_number), 703)

    def test_inventory_completed_heartbeat_timeout(self):
        serial_number = self.commit_minimal_ms_tree()
        event_cls = event_cls_from_type("jamf_computer_inventory_completed")
        self.assertEqual(event_cls.get_machine_heartbeat_timeout(serial_number), 7203)
