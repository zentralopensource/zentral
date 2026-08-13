import json
import logging

from django.core.files.storage import default_storage

from .distributed_query_result_stores import get_distributed_query_result_store
from .events import DISTRIBUTED_QUERY_RESULTS_ROUTING_KEY

logger = logging.getLogger("zentral.contrib.osquery.preprocessors")


class DistributedQueryResultsPreprocessor:
    routing_key = DISTRIBUTED_QUERY_RESULTS_ROUTING_KEY

    def process_raw_event(self, raw_event):
        try:
            distributed_query_pk = int(raw_event["distributed_query_pk"])
            serial_number = raw_event["serial_number"]
            rows = raw_event.get("rows")
            filepath = raw_event.get("filepath")
            if rows is None and not filepath:
                raise KeyError("missing rows and filepath")
        except (KeyError, TypeError, ValueError):
            logger.exception("Invalid distributed query result raw event")
            return []
        if rows is None:
            try:
                with default_storage.open(filepath) as f:
                    rows = json.load(f)
            except FileNotFoundError:
                # the file may have already been processed and deleted (queue re-delivery)
                logger.error("Missing distributed query %s result file %s", distributed_query_pk, filepath)
                return []
            except Exception:
                logger.exception("Could not read distributed query %s result file %s",
                                 distributed_query_pk, filepath)
                return []
        try:
            get_distributed_query_result_store().bulk_create(distributed_query_pk, serial_number, rows)
        except Exception:
            logger.exception("Could not store distributed query %s results for machine %s",
                             distributed_query_pk, serial_number)
            return []
        if filepath:
            try:
                default_storage.delete(filepath)
            except Exception:
                # the bucket lifecycle policy is the fallback
                logger.exception("Could not delete distributed query %s result file %s",
                                 distributed_query_pk, filepath)
        return []


def get_preprocessors():
    yield DistributedQueryResultsPreprocessor()
