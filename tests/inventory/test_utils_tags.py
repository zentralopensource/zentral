from unittest.mock import patch
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.models import MachineTag, Tag, Taxonomy
from zentral.contrib.inventory.utils import set_machine_taxonomy_tags


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
