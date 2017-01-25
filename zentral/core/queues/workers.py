from . import queues
from zentral.core.stores import stores
from zentral.core.events.processor import EventProcessor


def get_workers():
    for store in stores:
        yield queues.get_store_worker(store)
    yield queues.get_processor_worker(EventProcessor())
