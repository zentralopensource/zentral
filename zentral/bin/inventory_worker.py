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
from zentral.contrib.inventory.clients import clients, InventoryError

logger = logging.getLogger('zentral.bin.inventory_worker')

SLEEP = 20


def sync_inventory(client_name, worker_id):
    for client in clients:
        if client.name == client_name:
            break
    else:
        return
    while True:
        try:
            client.sync()
        except InventoryError:
            logger.exception("Inventory Error - %s - Sleeping 60s", client.name)
            time.sleep(60)
            logger.error("Inventory Error - %s - Resuming", client.name)
        time.sleep(SLEEP)


if __name__ == '__main__':
    p_l = []
    for client in clients:
        logger.error("Inventory worker %s", client.name)
        p = Process(target=sync_inventory, args=(client.name, 0))
        p.daemon = 1
        p.start()
        p_l.append(p)
    for p in p_l:
        p.join()
