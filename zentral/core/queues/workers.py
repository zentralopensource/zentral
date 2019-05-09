from importlib import import_module
from . import queues
from zentral.conf import settings
from zentral.core.stores import stores
from zentral.core.events.pipeline import enrich_event, process_event


def get_workers():
    yield queues.get_preprocess_worker()
    yield queues.get_enrich_worker(enrich_event)
    yield queues.get_process_worker(process_event)
    for store in stores:
        yield queues.get_store_worker(store)
    # extra apps workers
    for app in settings['apps']:
        try:
            workers_module = import_module("{}.workers".format(app))
        except ImportError as e:
            pass
        else:
            yield from getattr(workers_module, "get_workers")()
