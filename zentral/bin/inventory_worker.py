import os
import sys
ROOT_DIR = os.path.realpath(os.path.join(os.path.dirname(__file__), "../../server"))
sys.path.insert(0, ROOT_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'server.settings')
import django
django.setup()
import time
import uuid
from django.db import transaction
from zentral.contrib.inventory import inventory
from zentral.contrib.inventory.events import post_inventory_event
from zentral.core.metric_services import metric_services

SLEEP = 20


def sync_inventory():
    pk = uuid.uuid4()
    for index, (machine_snapshot, diff) in enumerate(inventory.sync()):
        if machine_snapshot.machine and machine_snapshot.machine.serial_number:
            post_inventory_event(machine_snapshot.machine.serial_number, diff, pk, index)
        else:
            print("Machine w/o serial number")


def push_inventory_metrics():
    metrics = inventory.metrics()
    for ms in metric_services.values():
        ms.push_metrics("zentral_inventory", metrics)

if __name__ == '__main__':
    while True:
        with transaction.atomic():
            sync_inventory()
        push_inventory_metrics()
        time.sleep(SLEEP)
