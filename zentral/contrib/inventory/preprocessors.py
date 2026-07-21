import logging
from django.db import InterfaceError, OperationalError
from zentral.core.queues.exceptions import RetryLater
from .utils import commit_machine_snapshot_and_yield_events


logger = logging.getLogger("zentral.contrib.inventory.preprocessors")


class MachineSnapshotPreprocessor:
    routing_key = "inventory_machine_snapshot"

    @staticmethod
    def _get_source_name_and_serial_number(ms_tree):
        source_name = serial_number = None
        if isinstance(ms_tree, dict):
            serial_number = ms_tree.get("serial_number")
            source = ms_tree.get("source")
            if isinstance(source, dict):
                source_name = source.get("name")
        return source_name or "UNKNOWN", serial_number or "UNKNOWN"

    def process_raw_event(self, raw_event):
        ms_tree = raw_event.get("ms_tree")
        try:
            yield from commit_machine_snapshot_and_yield_events(ms_tree)
        except (RetryLater, InterfaceError, OperationalError):
            # RetryLater and transient DB errors are recycled and re-enqueued by the worker
            # (iter_preprocessed_events); re-raise so the broad drop below never swallows them
            raise
        except Exception as error:
            # deterministic error: reprocessing the tree would fail the same way → drop it
            logger.error("Source %s, serial number %s: machine snapshot tree dropped: %s",
                         *self._get_source_name_and_serial_number(ms_tree), error)


def get_preprocessors():
    yield MachineSnapshotPreprocessor()
