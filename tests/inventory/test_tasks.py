from django.test import TestCase
from unittest.mock import patch
from zentral.contrib.inventory.events import InventoryCleanupFinished, InventoryCleanupStarted
from zentral.contrib.inventory.tasks import cleanup_inventory


class InventoryTasksTest(TestCase):
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cleanup_inventory(self, post_event):
        result = cleanup_inventory(17, {})
        self.assertTrue(all(tr["status"] == 0 for tr in result["tables"].values()))
        self.assertEqual(result["days"], 17)
        self.assertEqual(len(post_event.call_args_list), 2)
        first_event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(first_event, InventoryCleanupStarted)
        self.assertEqual(first_event.payload["cleanup"]["days"], 17)
        second_event = post_event.call_args_list[1].args[0]
        self.assertIsInstance(second_event, InventoryCleanupFinished)
        self.assertEqual(second_event.payload["cleanup"]["days"], 17)
