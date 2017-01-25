import logging
import time
from .clients import clients, InventoryError


logger = logging.getLogger("zentral.contrib.inventory.workers")


class InventoryWorker(object):
    sleep = 30

    def __init__(self, client):
        self.client = client
        self.name = "inventory worker {}".format(client.source["name"])

    def log_info(self, msg):
        logger.info("{} - {}".format(self.name, msg))

    def run(self):
        self.log_info("run")
        while True:
            try:
                self.client.sync()
            except InventoryError:
                logger.exception("Inventory client %s", self.client.name)
            self.log_info("sleep %s seconds" % self.sleep)
            time.sleep(self.sleep)
            self.log_info("resuming")


def get_workers():
    for client in clients:
        yield InventoryWorker(client)
