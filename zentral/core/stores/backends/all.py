from importlib import import_module
import logging
from django.db import models


logger = logging.getLogger("zentral.core.events.stores.all")


class StoreBackend(models.TextChoices):
    Datadog = "DATADOG", "Datadog"
    Elasticsearch = "ELASTICSEARCH", "Elasticsearch"
    HTTP = "HTTP", "HTTP"
    Kinesis = "KINESIS", "Kinesis"
    OpenSearch = "OPENSEARCH", "OpenSearch"
    Panther = "PANTHER", "Panther"
    Snowflake = "SNOWFLAKE", "Snowflake"
    Splunk = "SPLUNK", "Splunk"
    SumoLogic = "SUMO_LOGIC", "Sumo Logic"


def get_store_backend(store, load=False):
    backend = StoreBackend(store.backend)
    try:
        module = import_module(f"zentral.core.stores.backends.{backend.value.lower()}")
        backend_cls = getattr(module, f"{backend.name}Store")
    except (ImportError, AttributeError):
        logger.exception("Could not load store backend %s", backend)
    return backend_cls(store, load)
