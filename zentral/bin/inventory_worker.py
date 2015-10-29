import os
import sys
ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../"))
sys.path.insert(0, ROOT_DIR)
import time
import uuid
import zentral
zentral.setup()
from zentral.contrib.inventory import inventory
from zentral.contrib.inventory.events import post_inventory_event
from zentral.core.metric_services import metric_services

SLEEP = 20


def sync_inventory():
    pk = uuid.uuid4()
    for index, (machine_d, payload) in enumerate(inventory.sync()):
        post_inventory_event(machine_d['serial_number'], payload, pk, index)


def push_inventory_metrics():
    metrics = inventory.metrics()
    for ms in metric_services.values():
        ms.push_metrics("zentral_inventory", metrics)

if __name__ == '__main__':
    while True:
        sync_inventory()
        push_inventory_metrics()
        time.sleep(SLEEP)
