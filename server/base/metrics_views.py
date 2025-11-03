from prometheus_client import Gauge
from zentral.utils.prometheus import BasePrometheusMetricsView
from django_celery_results.models import TaskResult
from django.db.models import Count


class MetricsView(BasePrometheusMetricsView):
    def add_all_tasks(self):
        g = Gauge('zentral_base_tasks_bucket', 'Zentral Tasks Counter',
                  ['name', 'status'],
                  registry=self.registry)

        for task in TaskResult.objects.values(
            'task_name', 'status'
        ).annotate(
            count=Count('task_id')
        ).order_by('-count'):
            g.labels(
                name=task['task_name'] or "_",
                status=task['status']
            ).set(task['count'])

    def populate_registry(self):
        self.add_all_tasks()