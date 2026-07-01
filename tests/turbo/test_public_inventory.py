import gzip
import json
from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshot
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.contrib.turbo.events import TurboRequestEvent
from .utils import TurboPublicTestCase, force_configuration, force_enrolled_machine


class TurboInventoryPublicTestCase(TurboPublicTestCase):
    def _inventory(self, token, ms_tree):
        return self.client.post(
            reverse("turbo_public:inventory"),
            data=json.dumps(ms_tree),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def _inventory_encoded(self, token, body, encoding):
        return self.client.post(
            reverse("turbo_public:inventory"),
            data=body,
            content_type="application/json",
            HTTP_CONTENT_ENCODING=encoding,
            HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}",
        )

    def _enrolled(self):
        configuration = force_configuration()
        return force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)

    def test_inventory_unauthenticated(self):
        self.assertEqual(self.client.post(reverse("turbo_public:inventory")).status_code, 401)

    def test_inventory_invalid_json(self):
        _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:inventory"), data="not json",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)

    def test_inventory_not_a_dict(self):
        _, _, token = self._enrolled()
        response = self.client.post(reverse("turbo_public:inventory"), data="[]",
                                    content_type="application/json",
                                    HTTP_AUTHORIZATION=f"TurboEnrolledMachine {token}")
        self.assertEqual(response.status_code, 400)

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_commits_snapshot(self, post_machine_snapshot_raw_event):
        # mirror munki's test: commit synchronously so we can assert the snapshot landed in inventory
        post_machine_snapshot_raw_event.side_effect = commit_machine_snapshot_and_trigger_events
        _, serial_number, token = self._enrolled()
        computer_name = get_random_string(12)
        response = self._inventory(token, {"system_info": {"computer_name": computer_name}})
        self.assertEqual(response.status_code, 200)
        machine_snapshot = MachineSnapshot.objects.current().get(serial_number=serial_number)
        self.assertEqual(machine_snapshot.system_info.computer_name, computer_name)
        self.assertEqual(machine_snapshot.source.module, "zentral.contrib.turbo")
        self.assertEqual(machine_snapshot.reference, serial_number)

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_ignores_body_serial_number(self, post_machine_snapshot_raw_event):
        _, serial_number, token = self._enrolled()
        self._inventory(token, {"serial_number": "SOMEONE-ELSE", "system_info": {"computer_name": "x"}})
        tree = post_machine_snapshot_raw_event.call_args.args[0]
        # the authenticated machine's serial wins over whatever the body claimed
        self.assertEqual(tree["serial_number"], serial_number)
        self.assertEqual(tree["source"], {"module": "zentral.contrib.turbo", "name": "Turbo"})

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_stamps_business_unit_and_public_ip(self, post_machine_snapshot_raw_event):
        # the server stamps the enrollment's business unit and the request IP onto the snapshot
        enrollment, _, token = self._enrolled()
        self._inventory(token, {"system_info": {"computer_name": "x"}})
        tree = post_machine_snapshot_raw_event.call_args.args[0]
        self.assertEqual(tree["public_ip_address"], "127.0.0.1")
        self.assertEqual(tree["business_unit"], enrollment.secret.get_api_enrollment_business_unit().serialize())

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_keeps_snapshot_last_seen(self, post_machine_snapshot_raw_event):
        _, serial_number, token = self._enrolled()
        self._inventory(token, {"system_info": {"computer_name": "x"}, "last_seen": "2026-06-22T10:00:00"})
        tree = post_machine_snapshot_raw_event.call_args.args[0]
        self.assertEqual(tree["last_seen"], "2026-06-22T10:00:00")

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_missing_last_seen_falls_back_with_warning(self, post_machine_snapshot_raw_event):
        _, serial_number, token = self._enrolled()
        with self.assertLogs("zentral.contrib.turbo.public_views.inventory", level="WARNING") as cm:
            self._inventory(token, {"system_info": {"computer_name": "x"}})
        tree = post_machine_snapshot_raw_event.call_args.args[0]
        self.assertIsNotNone(tree["last_seen"])
        self.assertTrue(any("no last_seen" in line for line in cm.output))

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    def test_inventory_gzip_encoded(self, post_machine_snapshot_raw_event):
        _, serial_number, token = self._enrolled()
        computer_name = get_random_string(12)
        body = gzip.compress(json.dumps({"system_info": {"computer_name": computer_name}}).encode("utf-8"))
        response = self._inventory_encoded(token, body, "gzip")
        self.assertEqual(response.status_code, 200)
        tree = post_machine_snapshot_raw_event.call_args.args[0]
        self.assertEqual(tree["system_info"]["computer_name"], computer_name)
        self.assertEqual(tree["serial_number"], serial_number)

    def test_inventory_corrupt_gzip(self):
        _, _, token = self._enrolled()
        self.assertEqual(self._inventory_encoded(token, b"not gzip", "gzip").status_code, 400)

    @patch("zentral.contrib.turbo.public_views.inventory.post_machine_snapshot_raw_event")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_inventory_request_event(self, post_event, post_machine_snapshot_raw_event):
        configuration = force_configuration()
        enrollment, serial_number, token = force_enrolled_machine(
            configuration=configuration, meta_business_unit=self.mbu)
        with self.captureOnCommitCallbacks(execute=True):
            self._inventory(token, {"system_info": {"computer_name": get_random_string(12)}})
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], TurboRequestEvent)]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.payload["request_type"], "inventory")
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"]["turbo_configuration"], [str(configuration.pk)])
