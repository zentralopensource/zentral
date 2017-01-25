from importlib import import_module
from multiprocessing import Process
from django.core.management.base import BaseCommand
from zentral.conf import settings
from zentral.core.queues.workers import get_workers as get_queues_workers


class Command(BaseCommand):
    help = 'Run Zentral workers.'

    def add_arguments(self, parser):
        pass

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
        for worker in self.get_workers():
            p = Process(target=worker.run,
                        name=worker.name)
            p.daemon = 1
            p.start()
            processes.append(p)
        for p in processes:
            p.join()
