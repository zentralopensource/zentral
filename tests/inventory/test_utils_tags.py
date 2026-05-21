from unittest.mock import patch
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.models import MachineTag, Tag, Taxonomy
from zentral.contrib.inventory.utils import (
    set_machine_taxonomy_tags,
    set_machine_taxonomy_tags_and_yield_events,
)
from zentral.contrib.inventory.utils.tags import (
    iter_machine_tag_events,
    iter_machine_tag_events_with_event_request,
)
from zentral.core.events.base import EventRequest


class InventoryUtilsTagsTestCase(TestCase):
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_set_machine_taxonomy_tags(self, post_event):
        sn0 = get_random_string(12)
        sn1 = get_random_string(12)
        # tag to keep without taxonomy
        tk0 = Tag.objects.create(name=get_random_string(12))
        # tag to keep with other taxonomy
        tx1 = Taxonomy.objects.create(name=get_random_string(12))
        tk1 = Tag.objects.create(taxonomy=tx1, name=get_random_string(12))
        # taxonomy in scope
        tx2 = Taxonomy.objects.create(name=get_random_string(12))
        # tag to keep with taxonomy in scope
        tk2 = Tag.objects.create(taxonomy=tx2, name=get_random_string(12))
        # tag to remove with taxonomy in scope
        tr2 = Tag.objects.create(taxonomy=tx2, name=get_random_string(12))
        # existing tag to add with taxonomy in scope
        ta2 = Tag.objects.create(taxonomy=tx2, name=get_random_string(12))
        # non-existing tag to add
        ta3_name = get_random_string(12)
        # create all machine tags
        for sn in (sn0, sn1):
            for tag in (tk0, tk1, tk2, tr2):
                MachineTag.objects.create(serial_number=sn, tag=tag)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            set_machine_taxonomy_tags(sn1, tx2, [tk2.name, ta2.name, ta3_name])
        ta3 = Tag.objects.get(name=ta3_name)
        self.assertEqual(
            set(
                mt.tag
                for mt in MachineTag.objects.select_related("tag").filter(serial_number=sn0)
            ),
            {tk0, tk1, tk2, tr2}
        )
        self.assertEqual(
            set(
                mt.tag
                for mt in MachineTag.objects.select_related("tag").filter(serial_number=sn1)
            ),
            {tk0, tk1, tk2, ta2, ta3}
        )
        # events
        self.assertEqual(len(callbacks), 1)
        event1, event2, event3 = sorted(
            [c.args[0] for c in post_event.call_args_list],
            key=lambda e: (e.payload["action"], e.payload["tag"]["pk"])
        )
        self.assertIsInstance(event1, MachineTagEvent)
        self.assertEqual(
            event1.payload,
            {'action': 'added',
             'tag': {'name': ta2.name, 'pk': ta2.pk},
             'taxonomy': {'name': tx2.name, 'pk': tx2.pk}}
        )
        self.assertIsInstance(event2, MachineTagEvent)
        self.assertEqual(
            event2.payload,
            {'action': 'added',
             'tag': {'name': ta3.name, 'pk': ta3.pk},
             'taxonomy': {'name': tx2.name, 'pk': tx2.pk}}
        )
        self.assertIsInstance(event3, MachineTagEvent)
        self.assertEqual(
            event3.payload,
            {'action': 'removed',
             'tag': {'name': tr2.name, 'pk': tr2.pk},
             'taxonomy': {'name': tx2.name, 'pk': tx2.pk}}
        )

    # iter_machine_tag_events_with_event_request

    def test_iter_machine_tag_events_empty_results(self):
        self.assertEqual(list(iter_machine_tag_events_with_event_request([], None)), [])
        self.assertEqual(list(iter_machine_tag_events_with_event_request(None, None)), [])

    def test_iter_machine_tag_events_shared_uuid_monotonic_index(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        t1 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        t2 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        results = [
            (sn, MachineTagEvent.Action.ADDED, t1.pk, t1.name, tx.pk, tx.name),
            (sn, MachineTagEvent.Action.REMOVED, t2.pk, t2.name, tx.pk, tx.name),
        ]
        events = list(iter_machine_tag_events_with_event_request(results, None))
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0].metadata.uuid, events[1].metadata.uuid)
        self.assertEqual(events[0].metadata.index, 0)
        self.assertEqual(events[1].metadata.index, 1)
        self.assertEqual(events[0].payload["action"], "added")
        self.assertEqual(events[1].payload["action"], "removed")
        self.assertEqual(events[0].metadata.machine_serial_number, sn)

    def test_iter_machine_tag_events_accepts_raw_action_string(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        t1 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        results = [(sn, "added", t1.pk, t1.name, tx.pk, tx.name)]
        event, = list(iter_machine_tag_events_with_event_request(results, None))
        self.assertEqual(event.payload["action"], "added")

    def test_iter_machine_tag_events_passes_event_request_through(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        t1 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        results = [(sn, MachineTagEvent.Action.ADDED, t1.pk, t1.name, tx.pk, tx.name)]
        event_request = EventRequest(user_agent="ua", ip="1.2.3.4")
        event, = list(iter_machine_tag_events_with_event_request(results, event_request))
        self.assertIs(event.metadata.request, event_request)

    def test_iter_machine_tag_events_no_taxonomy_in_payload(self):
        sn = get_random_string(12)
        t1 = Tag.objects.create(name=get_random_string(12))
        results = [(sn, MachineTagEvent.Action.ADDED, t1.pk, t1.name, None, None)]
        event, = list(iter_machine_tag_events_with_event_request(results, None))
        self.assertNotIn("taxonomy", event.payload)

    # iter_machine_tag_events

    def test_iter_machine_tag_events_builds_event_request_from_http_request(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        t1 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        results = [(sn, MachineTagEvent.Action.ADDED, t1.pk, t1.name, tx.pk, tx.name)]
        request = RequestFactory().get("/", HTTP_USER_AGENT="ua")
        request.user = AnonymousUser()
        event, = list(iter_machine_tag_events(results, request=request))
        self.assertIsNotNone(event.metadata.request)
        self.assertEqual(event.metadata.request.user_agent, "ua")

    def test_iter_machine_tag_events_no_request_no_event_request(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        t1 = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        results = [(sn, MachineTagEvent.Action.ADDED, t1.pk, t1.name, tx.pk, tx.name)]
        event, = list(iter_machine_tag_events(results, request=None))
        self.assertIsNone(event.metadata.request)

    # set_machine_taxonomy_tags_and_yield_events

    def _build_taxonomy_fixture(self):
        sn = get_random_string(12)
        tx = Taxonomy.objects.create(name=get_random_string(12))
        keep = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        remove = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        add = Tag.objects.create(taxonomy=tx, name=get_random_string(12))
        MachineTag.objects.create(serial_number=sn, tag=keep)
        MachineTag.objects.create(serial_number=sn, tag=remove)
        return sn, tx, keep, remove, add

    @patch("zentral.contrib.inventory.utils.tags.transaction.on_commit")
    def test_set_machine_taxonomy_tags_and_yield_events_does_not_register_on_commit(self, on_commit):
        sn, tx, keep, _, add = self._build_taxonomy_fixture()
        # exhausting the generator must not register an on_commit callback
        list(set_machine_taxonomy_tags_and_yield_events(sn, tx, [keep.name, add.name]))
        on_commit.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_set_machine_taxonomy_tags_and_yield_events_applies_changes(self, post_event):
        sn, tx, keep, remove, add = self._build_taxonomy_fixture()
        list(set_machine_taxonomy_tags_and_yield_events(sn, tx, [keep.name, add.name]))
        self.assertEqual(
            {mt.tag for mt in MachineTag.objects.filter(serial_number=sn)},
            {keep, add},
        )
        # the generator yields events; nothing is posted by the helper itself
        post_event.assert_not_called()

    def test_set_machine_taxonomy_tags_and_yield_events_yields_expected_events(self):
        sn, tx, keep, remove, add = self._build_taxonomy_fixture()
        events = sorted(
            set_machine_taxonomy_tags_and_yield_events(sn, tx, [keep.name, add.name]),
            key=lambda e: (e.payload["action"], e.payload["tag"]["pk"]),
        )
        self.assertEqual(len(events), 2)
        added, removed = events
        self.assertEqual(added.payload["action"], "added")
        self.assertEqual(added.payload["tag"]["name"], add.name)
        self.assertEqual(added.payload["taxonomy"]["pk"], tx.pk)
        self.assertEqual(removed.payload["action"], "removed")
        self.assertEqual(removed.payload["tag"]["pk"], remove.pk)
        # shared event_uuid + monotonic index across yields
        self.assertEqual(added.metadata.uuid, removed.metadata.uuid)
        self.assertEqual({added.metadata.index, removed.metadata.index}, {0, 1})

    def test_set_machine_taxonomy_tags_and_yield_events_no_change_yields_nothing(self):
        sn, tx, keep, *_ = self._build_taxonomy_fixture()
        # only changing the row that already matches the desired state → no events
        # (but the `remove` tag is currently attached, so listing only `keep` would still remove it.
        # Use a list that matches current attached tags exactly for this taxonomy.)
        current = list(
            MachineTag.objects.filter(serial_number=sn, tag__taxonomy=tx).values_list("tag__name", flat=True)
        )
        events = list(set_machine_taxonomy_tags_and_yield_events(sn, tx, current))
        self.assertEqual(events, [])

    # parity: set_machine_taxonomy_tags still uses on_commit

    @patch("zentral.contrib.inventory.utils.tags.transaction.on_commit")
    def test_set_machine_taxonomy_tags_still_registers_on_commit(self, on_commit):
        sn, tx, keep, _, add = self._build_taxonomy_fixture()
        set_machine_taxonomy_tags(sn, tx, [keep.name, add.name])
        on_commit.assert_called_once()
