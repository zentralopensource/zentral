import os
import sys
ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, ROOT_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()
import logging
from multiprocessing import Process
from zentral.core.queues import queues
from zentral.core.stores import stores

logger = logging.getLogger('zentral.bin.store_worker')


def store_events(worker_id, store_name):
    for store in stores:
        if store.name == store_name:
            break
    else:
        return
    store_worker = queues.get_store_worker(store)
    store_worker.run()


if __name__ == '__main__':
    p_l = []
    for store in stores:
        store.wait_and_configure()
        p = Process(target=store_events, args=(0, store.name))
        p.daemon = 1
        p.start()
        p_l.append(p)
    for p in p_l:
        p.join()
