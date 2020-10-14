import json
import logging
from multiprocessing import Process
import random
import time
import yaml
from django.core.management.base import BaseCommand
from zentral.core.queues.workers import get_workers


logger = logging.getLogger("zentral.server.base.management.commands.runworkers")


class Command(BaseCommand):
    help = 'Run Zentral workers.'
    RESTART_DELAY = (10, 20)  # range for the restart delay in seconds

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

        # prometheus metrics exporter
        parser.add_argument("--prometheus", action="store_true")
        parser.add_argument("--prometheus-sd-file")
        parser.add_argument("--prometheus-base-port", type=int, default=9900)
        parser.add_argument("--external-hostname", default="localhost")

        # statsd metrics exporter
        parser.add_argument("--statsd", action="store_true")
        parser.add_argument("--statsd-host", default="localhost")
        parser.add_argument("--statsd-port", type=int, default=9125)
        parser.add_argument("--statsd-prefix", default="zentral")

        parser.add_argument("worker", nargs="*")

    def start_worker(self, idx, worker):
        logger.info("Starting worker '%s'", worker.name)
        metrics_exporter = None
        if self.prometheus:
            from zentral.utils.prometheus import PrometheusMetricsExporter
            prometheus_port = self.prometheus_base_port + idx
            metrics_exporter = PrometheusMetricsExporter(prometheus_port)
        elif self.statsd:
            from zentral.utils.statsd import StatsdMetricsExporter
            metrics_exporter = StatsdMetricsExporter(self.statsd_host, self.statsd_port, self.statsd_prefix)
        p = Process(target=worker.run,
                    kwargs={"metrics_exporter": metrics_exporter},
                    name=worker.name)
        p.daemon = 1
        p.start()
        self.processes[idx] = (worker, p)
        if self.prometheus:
            self.prometheus_targets[idx] = {
                "targets": ["{}:{}".format(self.external_hostname, prometheus_port)],
                "labels": {"job": worker.name}
            }

    def write_prometheus_sd_file(self):
        if self.prometheus_sd_file:
            with open(self.prometheus_sd_file, "w") as f:
                yaml.dump(list(self.prometheus_targets.values()), f, allow_unicode=True)

    def watch_workers(self):
        while True:
            time.sleep(random.uniform(1, 3))
            for idx, (worker, p) in self.processes.items():
                if idx in self.processes_to_restart:
                    continue
                if not p.is_alive() or (p.exitcode is not None and p.exitcode < 0):
                    proc_is_dead = True
                    p_exitcode = p.exitcode  # not accessible after the close()
                    try:
                        p.close()
                    except AttributeError:
                        pass  # python < 3.7
                    except ValueError:
                        # TODO the proc is not dead?
                        # should not happen
                        logger.error("The worker '%s' is not really dead.", worker.name)
                        proc_is_dead = False
                    if proc_is_dead:
                        delay = random.uniform(*self.RESTART_DELAY)
                        logger.error("Worker '%s' is dead. Exit code %s. Restarting in %ss",
                                     worker.name,  -1 * p_exitcode, int(delay))
                        self.processes_to_restart[idx] = (time.time() + delay, worker)
                else:
                    logger.debug("Worker '%s' OK", worker.name)
            for idx, (deadline, worker) in list(self.processes_to_restart.items()):
                if deadline < time.time():
                    print("OUPS", flush=True)
                    self.start_worker(idx, worker)
                    self.processes_to_restart.pop(idx)

    def handle(self, *args, **options):
        list_workers = options['list_workers']
        json_output = options['json_output']

        # prometheus metrics exporter
        self.prometheus = options['prometheus']
        self.prometheus_sd_file = None if list_workers else options.get('prometheus_sd_file')
        self.prometheus_base_port = options['prometheus_base_port']
        self.external_hostname = options['external_hostname']

        # statsd metrics exporter
        self.statsd = options['statsd']
        self.statsd_host = options['statsd_host']
        self.statsd_port = options['statsd_port']
        self.statsd_prefix = options['statsd_prefix']

        workers = options['worker']
        all_workers = []
        for idx, worker in enumerate(sorted(get_workers(), key=lambda w: w.name)):
            if list_workers:
                all_workers.append(worker.name)
                continue
            elif workers and worker.name not in workers:
                continue
            self.start_worker(idx, worker)
        if list_workers:
            if json_output:
                print(json.dumps({"workers": all_workers}))
            else:
                for worker_name in all_workers:
                    print("Worker '{}'".format(worker_name))
        if self.processes:
            if self.prometheus:
                self.write_prometheus_sd_file()
            self.watch_workers()
