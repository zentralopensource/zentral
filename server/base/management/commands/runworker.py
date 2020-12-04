import json
import logging
import sys
from django.core.management.base import BaseCommand
from zentral.core.queues.workers import get_workers


logger = logging.getLogger("zentral.server.base.management.commands.runworker")


class Command(BaseCommand):
    help = 'Run Zentral worker'

    @staticmethod
    def add_arguments(parser):
        parser.add_argument('--list-workers', action='store_true', dest='list_workers', default=False,
                            help='list workers')
        parser.add_argument('--json', action='store_true', dest='json_output', default=False,
                            help='output workers list in json format')

        # prometheus metrics exporter
        parser.add_argument("--prometheus", action="store_true")
        parser.add_argument("--prometheus-port", type=int, default=9900)

        # statsd metrics exporter
        parser.add_argument("--statsd", action="store_true")
        parser.add_argument("--statsd-host", default="localhost")
        parser.add_argument("--statsd-port", type=int, default=9125)
        parser.add_argument("--statsd-prefix", default="zentral")

        parser.add_argument("worker", nargs="?")

    @staticmethod
    def _get_workers(list_workers, requested_worker_name):
        all_workers = []
        found_worker = None
        for idx, worker in enumerate(sorted(get_workers(), key=lambda w: w.name)):
            if list_workers:
                all_workers.append(worker.name)
                continue
            elif requested_worker_name and worker.name == requested_worker_name:
                found_worker = worker
                break
        return all_workers, found_worker

    @staticmethod
    def _start_worker(found_worker, options):
        logger.info("Start worker '%s'", found_worker.name)

        metrics_exporter = None
        if options['prometheus']:
            from zentral.utils.prometheus import PrometheusMetricsExporter
            metrics_exporter = PrometheusMetricsExporter(
                options['prometheus_port']
            )
        elif options['statsd']:
            from zentral.utils.statsd import StatsdMetricsExporter
            metrics_exporter = StatsdMetricsExporter(
                options['statsd_host'],
                options['statsd_port'],
                options['statsd_prefix']
            )

        found_worker.run(metrics_exporter=metrics_exporter)

    @staticmethod
    def _output_worker_list(all_workers, options):
        if options['json_output']:
            print(json.dumps({"workers": all_workers}))
        else:
            for worker_name in all_workers:
                print("Worker '{}'".format(worker_name))

    def handle(self, *args, **options):
        list_workers = options['list_workers']
        requested_worker_name = options.get('worker', None)
        if not list_workers and not requested_worker_name:
            logger.error("'runworker' missing argument: --list-workers or a worker name")
            sys.exit(1)
        all_workers, found_worker = self._get_workers(list_workers, requested_worker_name)
        if not list_workers and found_worker is None:
            logger.error("Worker '%s' not found", requested_worker_name)
            sys.exit(1)
        elif found_worker:
            self._start_worker(found_worker, options)
        else:
            self._output_worker_list(all_workers, options)
