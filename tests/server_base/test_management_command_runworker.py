from io import StringIO
import json
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from zentral.core.stores.conf import stores
from zentral.utils.prometheus import PrometheusMetricsExporter
from zentral.utils.provisioning import provision


class RunWorkerBaseManagementCommandsTest(TestCase):
    def test_missing_argument(self):
        with self.assertRaises(SystemExit) as ctx:
            call_command('runworker')
        self.assertEqual(ctx.exception.args, (100,))

    def test_worker_not_found(self):
        with self.assertRaises(SystemExit) as ctx:
            call_command('runworker', 'yolo')
        self.assertEqual(ctx.exception.args, (101,))

    def test_list_workers_json(self):
        provision()  # provision the stores
        stores._load(force=True)  # reload the stores
        out = StringIO()
        call_command('runworker', "--list-workers", "--json", stdout=out)
        self.assertEqual(
            json.loads(out.getvalue()),
            {'workers': [
                'preprocess worker',
                'enrich worker',
                'process worker',
                'inventory worker dummy',
                'APNS worker devices',
                'APNS worker users',
                'store worker Elasticsearch',
             ]},
        )

    def test_list_workers_text(self):
        provision()  # provision the stores
        stores._load(force=True)  # reload the stores
        out = StringIO()
        call_command('runworker', "--list-workers", stdout=out)
        self.assertEqual(
            out.getvalue(),
            "Worker 'preprocess worker'\n"
            "Worker 'enrich worker'\n"
            "Worker 'process worker'\n"
            "Worker 'inventory worker dummy'\n"
            "Worker 'APNS worker devices'\n"
            "Worker 'APNS worker users'\n"
            "Worker 'store worker Elasticsearch'\n"
        )

    @patch("zentral.core.queues.backends.kombu.PreprocessWorker.run")
    def test_start_worker_prometheus(self, run):
        call_command('runworker', 'preprocess worker', '--prometheus', '--prometheus-port', '9910')
        run.assert_called_once()
        self.assertEqual(list(run.call_args_list[0].kwargs.keys()), ["metrics_exporter"])
        metrics_exporter = run.call_args_list[0].kwargs["metrics_exporter"]
        self.assertIsInstance(metrics_exporter, PrometheusMetricsExporter)
        self.assertEqual(metrics_exporter.port, 9910)
        self.assertEqual(metrics_exporter.default_labels, ["worker"])
        self.assertEqual(metrics_exporter.default_label_values, ("preprocess worker",))
