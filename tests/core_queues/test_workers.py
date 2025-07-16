from django.test import TestCase
from zentral.core.queues.workers import get_workers
from zentral.utils.provisioning import provision


class QueuesWorkersTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()

    def test_workers(self):
        worker_names = set(w.name for w in get_workers())
        self.assertEqual(
            worker_names,
            {"inventory worker dummy",
             "preprocess worker", "enrich worker", "process worker",
             "store worker Elasticsearch",
             "APNS worker devices", "APNS worker users"}
        )
