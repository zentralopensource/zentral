from io import StringIO
import json
from unittest.mock import patch
from django.core.management import call_command
from django.test import TestCase
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


class RunWorkersBaseManagementCommandsTest(TestCase):
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

    @patch("base.management.commands.runworkers.Command.watch_workers")
    @patch("base.management.commands.runworkers.Process.start")
    def test_start_worker_prometheus(self, start, watch_workers):
        call_command('runworkers', 'enrich worker', '--prometheus', '--prometheus-base-port', '9910')
        # TODO: better tests
        start.assert_called_once()
        watch_workers.assert_called_once()
