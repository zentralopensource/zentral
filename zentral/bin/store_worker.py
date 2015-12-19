import os
import sys
ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, ROOT_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()
import logging
import time
from multiprocessing import Process
from zentral.core.queues import queues
from zentral.core.queues.exceptions import TemporaryQueueError
from zentral.core.stores import stores

logger = logging.getLogger('zentral.bin.store_worker')


def store_events(store_name, worker_id):
    for store in stores:
        if store.name == store_name:
            break
    else:
        return
    while True:
        while True:
            try:
                event_id, event = queues.get_store_event_job(store.name, worker_id)
            except TemporaryQueueError:
                logger.exception('Could not get new store job')
                time.sleep(5)
            else:
                break
        while True:
            try:
                store.store(event)
            except:
                logger.exception('Could not store event in store %s', store_name)
                time.sleep(5)
            else:
                break
        while True:
            try:
                queues.ack_store_event_job(store.name, worker_id, event_id)
            except TemporaryQueueError:
                logger.exception('Could not hack store job')
                time.sleep(5)
            else:
                break

if __name__ == '__main__':
    p_l = []
    for store in stores:
        p = Process(target=store_events, args=(store.name, 0))
        p.daemon = 1
        p.start()
        p_l.append(p)
    for p in p_l:
        p.join()
