import json
import logging
import sys
from django.core.management.base import BaseCommand
from zentral.core.queues.workers import get_workers


logger = logging.getLogger("zentral.server.base.management.commands.runworker")


class Command(BaseCommand):
    help = 'Run Zentral worker'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processes = {}
        self.prometheus_targets = {}
        self.processes_to_restart = {}

    def add_arguments(self, parser):
        parser.add_argument('--list-workers', action='store_true', dest='list_workers', default=False,
                            help='list workers')
        parser.add_argument('--json', action='store_true', dest='json_output', default=False,
                            help='output workers list in json format')
        parser.add_argument("worker", nargs="?")

    def handle(self, *args, **options):
        list_workers = options['list_workers']
        json_output = options['json_output']
        requested_worker_name = options.get('worker', None)
        if not list_workers and not requested_worker_name:
            logger.error("'runworker' missing argument: --list-workers or a worker name")
            sys.exit(1)
        found_worker = None
        all_workers = []
        for idx, worker in enumerate(sorted(get_workers(), key=lambda w: w.name)):
            if list_workers:
                all_workers.append(worker.name)
                continue
            elif requested_worker_name and worker.name == requested_worker_name:
                found_worker = worker
        if not list_workers and found_worker is None:
            logger.error("Worker '%s' not found", requested_worker_name)
            sys.exit(1)
        elif found_worker:
            logger.info("Start worker '%s'", found_worker.name)
            found_worker.run()
        else:
            if json_output:
                print(json.dumps({"workers": all_workers}))
            else:
                for worker_name in all_workers:
                    print("Worker '{}'".format(worker_name))
