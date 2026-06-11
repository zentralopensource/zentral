from importlib import import_module

from django.core.exceptions import ImproperlyConfigured

from zentral.conf import settings

DEFAULT_TTL_DAYS = 90


def _serialize_config(config):
    serialize = getattr(config, "serialize", None)
    return serialize() if serialize else dict(config)


def _load_distributed_query_result_store():
    app_config_d = settings["apps"]["zentral.contrib.osquery"]
    ttl_days = app_config_d.get("distributed_query_results_ttl_days", DEFAULT_TTL_DAYS)
    try:
        ttl_days = int(ttl_days)
        if ttl_days < 1:
            raise ValueError
    except (TypeError, ValueError):
        raise ImproperlyConfigured("Invalid distributed_query_results_ttl_days app setting")
    store_config_d = app_config_d.get("distributed_query_result_store")
    if store_config_d:
        backend = store_config_d["backend"].lower()
        backend_config_d = store_config_d.get(f"{backend}_kwargs")
        config_d = _serialize_config(backend_config_d) if backend_config_d else {}
    else:
        backend = "postgres"
        config_d = {}
    module = import_module(f"zentral.contrib.osquery.distributed_query_result_stores.{backend}")
    return module.DistributedQueryResultStore(config_d, ttl_days)


_store = None


def get_distributed_query_result_store():
    global _store
    if _store is None:
        _store = _load_distributed_query_result_store()
    return _store
