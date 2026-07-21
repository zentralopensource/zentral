import logging
from django.db import InterfaceError, OperationalError, close_old_connections
from zentral.core.queues.exceptions import RetryLater


logger = logging.getLogger("zentral.core.queues.preprocessing")


def iter_preprocessed_events(preprocessors, routing_key, raw_event):
    # Single entry point every queue backend uses to run a preprocessor: resolve the one for
    # the routing key, yield the events it produces, and recycle a dead pooled connection.
    #
    # Preprocessors run in a long-lived worker with no request cycle, so Django never recycles
    # their pooled connection (CONN_HEALTH_CHECKS / CONN_MAX_AGE are driven by the request
    # signals). When a pooler/proxy drops an idle connection, the next commit raises
    # InterfaceError/OperationalError: drop the dead connection so the retry and the following
    # messages reconnect, then re-enqueue with RetryLater. A RetryLater raised by a preprocessor
    # (e.g. an API rate limit) passes straight through.
    if not routing_key:
        logger.error("Message without routing key")
        return
    preprocessor = preprocessors.get(routing_key)
    if not preprocessor:
        logger.error("No preprocessor for routing key %s", routing_key)
        return
    try:
        yield from preprocessor.process_raw_event(raw_event)
    except (InterfaceError, OperationalError) as error:
        logger.error("Preprocessor %s: recoverable DB error, re-enqueuing: %s", routing_key, error)
        close_old_connections()
        raise RetryLater
