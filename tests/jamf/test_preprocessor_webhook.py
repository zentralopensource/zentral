from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import ArchiveMachine, MachineTagEvent
from zentral.contrib.inventory.models import (CurrentMachineSnapshot, MachineSnapshotCommit,
                                              MachineTag, Tag, Taxonomy)
from zentral.contrib.jamf.api_client import APIClientError
from zentral.contrib.jamf.preprocessors.webhook import WebhookEventPreprocessor


LOGGER_NAME = "zentral.contrib.jamf.preprocessors.webhook"


class WebhookEventPreprocessorTagsTestCase(TestCase):
    def _make_preprocessor(self):
        return WebhookEventPreprocessor()

    def _make_mocked_client(self, serial_number, tags):
        client = MagicMock()
        client.source_repr = "test.example.com"
        client.get_machine_d_and_tags.return_value = (
            {"serial_number": serial_number},
            tags,
        )
        return client

    def _drain(self, preprocessor, client):
        # consume the generator inside the same thread, mirroring the queue worker
        return list(preprocessor._update_machine(client, "computer", 1))

    @patch("zentral.contrib.jamf.preprocessors.webhook.commit_machine_snapshot_and_yield_events")
    def test_update_machine_yields_tag_events(self, commit_machine_snapshot):
        commit_machine_snapshot.return_value = iter([])  # focus on the tag-events path
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        existing_tag = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        stale_tag = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        MachineTag.objects.create(serial_number=sn, tag=existing_tag)
        MachineTag.objects.create(serial_number=sn, tag=stale_tag)

        new_tag_name = get_random_string(12)
        client = self._make_mocked_client(sn, {tx.pk: [existing_tag.name, new_tag_name]})
        events = self._drain(self._make_preprocessor(), client)

        tag_events = [e for e in events if isinstance(e, MachineTagEvent)]
        self.assertEqual(len(tag_events), 2)
        actions = sorted((e.payload["action"], e.payload["tag"]["name"]) for e in tag_events)
        self.assertEqual(actions, sorted([("added", new_tag_name), ("removed", stale_tag.name)]))
        for event in tag_events:
            self.assertEqual(event.metadata.machine_serial_number, sn)
            self.assertEqual(event.payload["taxonomy"]["pk"], tx.pk)

    @patch("zentral.contrib.inventory.utils.tags.transaction.on_commit")
    @patch("zentral.contrib.jamf.preprocessors.webhook.commit_machine_snapshot_and_yield_events")
    def test_update_machine_does_not_register_on_commit_for_tag_events(
        self, commit_machine_snapshot, on_commit,
    ):
        # this is the regression-catcher for the original bug: tag events must NOT
        # go through transaction.on_commit (which is what spawned the orphaned thread)
        commit_machine_snapshot.return_value = iter([])
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        existing_tag = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        MachineTag.objects.create(serial_number=sn, tag=existing_tag)
        client = self._make_mocked_client(sn, {tx.pk: [existing_tag.name, get_random_string(12)]})
        self._drain(self._make_preprocessor(), client)
        on_commit.assert_not_called()

    @patch("zentral.contrib.jamf.preprocessors.webhook.commit_machine_snapshot_and_yield_events")
    def test_update_machine_no_tags_no_tag_events(self, commit_machine_snapshot):
        commit_machine_snapshot.return_value = iter([])
        sn = get_random_string(12)
        client = self._make_mocked_client(sn, {})
        events = self._drain(self._make_preprocessor(), client)
        self.assertEqual([e for e in events if isinstance(e, MachineTagEvent)], [])

    @patch("zentral.contrib.jamf.preprocessors.webhook.commit_machine_snapshot_and_yield_events")
    def test_update_machine_unknown_taxonomy_skipped(self, commit_machine_snapshot):
        commit_machine_snapshot.return_value = iter([])
        sn = get_random_string(12)
        client = self._make_mocked_client(sn, {999999: ["whatever"]})
        events = self._drain(self._make_preprocessor(), client)
        self.assertEqual([e for e in events if isinstance(e, MachineTagEvent)], [])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.jamf.preprocessors.webhook.commit_machine_snapshot_and_yield_events")
    def test_update_machine_does_not_post_events_itself(self, commit_machine_snapshot, post_event):
        # the preprocessor must not post events; that is the caller's responsibility.
        # this guards against any future regression that re-introduces side-effect posting.
        commit_machine_snapshot.return_value = iter([])
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        client = self._make_mocked_client(sn, {tx.pk: [get_random_string(12)]})
        self._drain(self._make_preprocessor(), client)
        post_event.assert_not_called()


class WebhookEventPreprocessorArchiveTestCase(TestCase):
    # a fresh dict every time: committing a machine snapshot tree adds the mt hashes in place
    @staticmethod
    def _source_d():
        return {"module": "zentral.contrib.jamf", "name": "jamf",
                "config": {"host": "jamf.example.com", "path": "/JSSResource", "port": 443}}

    def _make_client(self, machine_d_and_tags):
        client = MagicMock()
        client.source_repr = "jamf.example.com"
        client.get_source_d.return_value = self._source_d()
        client.machine_reference.side_effect = "{},{}".format
        client.get_machine_d_and_tags.return_value = machine_d_and_tags
        return client

    def _commit_jamf_machine(self, jamf_id):
        serial_number = get_random_string(12)
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": self._source_d(),
            "reference": "computer,{}".format(jamf_id),
            "serial_number": serial_number,
        })
        return serial_number

    def _drain(self, client, jamf_id):
        return list(WebhookEventPreprocessor()._update_machine(client, "computer", jamf_id))

    def test_machine_gone_from_jamf_is_archived(self):
        serial_number = self._commit_jamf_machine(42)
        qs = CurrentMachineSnapshot.objects.filter(serial_number=serial_number)
        self.assertEqual(qs.count(), 1)

        with self.assertLogs(LOGGER_NAME, level="INFO") as cm:
            events = self._drain(self._make_client(None), 42)
        self.assertIn("INFO:{}:Archive machine jamf.example.com computer 42".format(LOGGER_NAME),
                      cm.output)

        self.assertEqual(qs.count(), 0)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIsInstance(event, ArchiveMachine)
        self.assertEqual(event.metadata.machine_serial_number, serial_number)
        self.assertEqual(event.payload, {"sources": [self._source_d()]})

    def test_machine_gone_from_jamf_keeps_the_other_sources(self):
        serial_number = self._commit_jamf_machine(42)
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": serial_number,
        })

        self._drain(self._make_client(None), 42)

        remaining = list(CurrentMachineSnapshot.objects.filter(serial_number=serial_number)
                                                       .select_related("source"))
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].source.name, "Zentral Tests")

    def test_machine_gone_from_jamf_without_current_snapshot(self):
        # nothing is archived, so nothing says it was
        with self.assertLogs(LOGGER_NAME, level="INFO") as cm:
            self.assertEqual(self._drain(self._make_client(None), 4242), [])
        self.assertEqual([r for r in cm.output if "Archive machine" in r], [])

    def test_api_error_does_not_archive(self):
        # only a 404 archives: any other failure must leave the inventory alone,
        # so that a Jamf outage cannot drop the current snapshots of a whole fleet
        serial_number = self._commit_jamf_machine(42)
        client = self._make_client(None)
        client.get_machine_d_and_tags.side_effect = APIClientError("boom")

        self.assertEqual(self._drain(client, 42), [])

        self.assertEqual(CurrentMachineSnapshot.objects.filter(serial_number=serial_number).count(), 1)
