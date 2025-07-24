from importlib import import_module
from . import queues
from zentral.conf import settings
from zentral.core.stores.conf import stores
from zentral.core.events.pipeline import enrich_event, process_event


def get_workers():
    # IMPORTANT the yield sequence is important to get stable prometheus ports
    # core app workers
    yield queues.get_preprocess_worker()
    yield queues.get_enrich_worker(enrich_event)
    yield queues.get_process_worker(process_event)
    # extra app workers
    for app in settings['apps']:
        try:
            workers_module = import_module("{}.workers".format(app))
        except ImportError:
            pass
        else:
            yield from getattr(workers_module, "get_workers")()
    # store workers (dynamic, but sorted by creation date)
    for store in stores.iter_queue_worker_stores():
        yield queues.get_store_worker(store)
