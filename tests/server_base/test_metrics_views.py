from datetime import datetime, timedelta
from django.urls import reverse
from django.test import TestCase

from prometheus_client.parser import text_string_to_metric_families
import uuid
from django_celery_results.models import TaskResult


class PrometheusViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="zentral.base.tasks.export_targets",
            status='SUCCESS',
            worker="celery@000000000000",
            content_type='application/json',
            content_encoding='utf-8',
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1),
            meta='{"children": []}'
        )
        TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="zentral.base.tasks.export_targets",
            status='SUCCESS',
            worker="celery@000000000000",
            content_type='application/json',
            content_encoding='utf-8',
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1),
            meta='{"children": []}'
        )
        TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="zentral.base.tasks.export_targets",
            status='FAILURE',
            worker="celery@000000000000",
            content_type='application/json',
            content_encoding='utf-8',
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1),
            meta='{"children": []}'
        )
        TaskResult.objects.create(
            task_id=str(uuid.uuid4()),
            task_name="zentral.base.tasks.export_tasks",
            status='SUCCESS',
            worker="celery@000000000000",
            content_type='application/json',
            content_encoding='utf-8',
            result={},
            date_created=datetime.utcnow() - timedelta(days=1, seconds=10),
            date_done=datetime.utcnow() - timedelta(days=1),
            meta='{"children": []}'
        )
    # utils

    def _assertSamples(self, families, samples, only_family=None):
        d = {}
        for family in families:
            if only_family and only_family != family.name:
                continue
            sample_dict = d.setdefault(family.name, {})
            for sample in family.samples:
                serialized_sample_items = []
                for label in sorted(sample.labels.keys()):
                    serialized_sample_items.append(label)
                    serialized_sample_items.append(sample.labels[label])
                sample_dict[tuple(serialized_sample_items)] = sample.value
        self.assertEqual(d, samples)

    # tests

    def test_prometheus_metrics_403(self):
        response = self.client.get(reverse("base_metrics:all"))
        self.assertEqual(response.status_code, 403)

    def test_prometheus_metrics_tasks(self):
        response = self.client.get(
            reverse("base_metrics:all"), HTTP_AUTHORIZATION="Bearer CHANGE ME!!!"
        )
        self.assertEqual(response.status_code, 200)
        self._assertSamples(
            text_string_to_metric_families(response.content.decode("utf-8")),
            {
                'zentral_base_tasks_bucket': {
                    ('name', "zentral.base.tasks.export_targets", 'status', 'SUCCESS'): 2.0,
                    ('name', "zentral.base.tasks.export_targets", 'status', 'FAILURE'): 1.0,
                    ('name', "zentral.base.tasks.export_tasks", 'status', 'SUCCESS'): 1.0
                },
            },
            only_family="zentral_base_tasks_bucket",
        )
