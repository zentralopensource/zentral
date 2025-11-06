import logging
from .utils import commit_machine_snapshot_and_yield_events


logger = logging.getLogger("zentral.contrib.inventory.preprocessors")


class MachineSnapshotPreprocessor:
    routing_key = "inventory_machine_snapshot"

    def process_raw_event(self, raw_event):
        yield from commit_machine_snapshot_and_yield_events(raw_event["ms_tree"])


def get_preprocessors():
    yield MachineSnapshotPreprocessor()
