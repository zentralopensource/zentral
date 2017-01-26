from importlib import import_module
from multiprocessing import Process
from django.core.management.base import BaseCommand
from zentral.conf import settings
from zentral.core.queues.workers import get_workers as get_queues_workers


class Command(BaseCommand):
    help = 'Run Zentral workers.'

    def add_arguments(self, parser):
        parser.add_argument("--prometheus-base-port", type=int, default=9900)

    def get_workers(self):
        for app in settings['apps']:
            try:
                workers_module = import_module("{}.workers".format(app))
            except ImportError as e:
                pass
            else:
                yield from getattr(workers_module, "get_workers")()
        yield from get_queues_workers()

    def handle(self, *args, **kwargs):
        processes = []
        prometheus_base_port = kwargs['prometheus_base_port']
        for idx, worker in enumerate(sorted(self.get_workers(), key=lambda w: w.name)):
            p = Process(target=worker.run,
                        kwargs={"prometheus_port": prometheus_base_port + idx},
                        name=worker.name)
            p.daemon = 1
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
