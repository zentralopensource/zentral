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
        parser.add_argument("--prometheus-base-port", type=int, default=9900)
        parser.add_argument("--prometheus-sd-file")
        parser.add_argument("--external-hostname", default="localhost")
        parser.add_argument("worker", nargs="*")

    def start_worker(self, idx, worker):
        logger.info("Starting worker '%s'", worker.name)
        prometheus_port = self.prometheus_base_port + idx
        p = Process(target=worker.run,
                    kwargs={"prometheus_port": prometheus_port},
                    name=worker.name)
        p.daemon = 1
        p.start()
        self.processes[idx] = (worker, p)
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
                    self.start_worker(idx, worker)
                    self.processes_to_restart.pop(idx)

    def handle(self, *args, **options):
        list_workers = options['list_workers']
        self.prometheus_base_port = options['prometheus_base_port']
        self.prometheus_sd_file = None if list_workers else options.get('prometheus_sd_file')
        self.external_hostname = options['external_hostname']
        workers = options['worker']
        for idx, worker in enumerate(sorted(get_workers(), key=lambda w: w.name)):
            if list_workers:
                print("Worker '{}'".format(worker.name))
                continue
            elif workers and worker.name not in workers:
                continue
            self.start_worker(idx, worker)
        self.write_prometheus_sd_file()
        self.watch_workers()
