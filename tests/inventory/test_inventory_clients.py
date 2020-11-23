from django.test import SimpleTestCase
from zentral.contrib.inventory.workers import get_workers


class InventoryClientsTestCase(SimpleTestCase):
    def test_source(self):
        worker_count = 0
        for worker in get_workers():
            worker_count += 1
            self.assertTrue(isinstance(worker.client.source["config"], dict))
        self.assertTrue(worker_count > 0)
