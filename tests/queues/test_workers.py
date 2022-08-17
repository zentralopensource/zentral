from django.test import SimpleTestCase
from zentral.core.queues.workers import get_workers


class QueuesWorkersTestCase(SimpleTestCase):
    maxDiff = None

    def test_workers(self):
        worker_names = set(w.name for w in get_workers())
        self.assertEqual(
            worker_names,
            {"inventory worker dummy",
             "preprocess worker", "enrich worker", "process worker",
             "store worker elasticsearch"}
        )
