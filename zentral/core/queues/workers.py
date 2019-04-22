from . import queues
from zentral.core.stores import stores
from zentral.core.events.pipeline import enrich_event, process_event


def get_workers():
    yield queues.get_enrich_worker(enrich_event)
    yield queues.get_process_worker(process_event)
    for store in stores:
        yield queues.get_store_worker(store)
