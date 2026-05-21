from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.models import MachineTag, Tag, Taxonomy
from zentral.contrib.jamf.preprocessors.webhook import WebhookEventPreprocessor


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
