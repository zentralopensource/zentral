import logging
import os
import threading
import time
from typing import Optional
import weakref
from cedarpy import is_authorized, is_authorized_batch
from base.notifier import notifier
from .entities import Entity, Request


logger = logging.getLogger("zentral.accounts.pbac.cedar")


class PoliciesCache:
    max_age_seconds = 300

    def __init__(self, with_sync=False):
        self._concatenated_policies = None
        self._last_refresh_ts = None
        self._lock = threading.Lock()
        self.with_sync = with_sync
        self._sync_started = False

    def clear(self, *args, **kwargs):
        with self._lock:
            self._concatenated_policies = None
            logger.debug("Policies cache sync cleared")

    def _start_sync(self):
        if self.with_sync:
            if not self._sync_started:
                notifier.add_callback("policies.change", weakref.WeakMethod(self.clear))
                logger.debug("Policies cache sync started")
                self._sync_started = True

    def _refresh(self):
        self._start_sync()
        if (
            self.with_sync
            and self._concatenated_policies is not None
            and self._last_refresh_ts is not None
            and time.monotonic() - self._last_refresh_ts <= self.max_age_seconds
        ):
            logger.debug("Policies cache up to date")
            return
        logger.debug("Refresh policies cache")
        from accounts.models import Policy  # TODO reorganize to fix circular import?
        self._concatenated_policies = "\n".join(
            p.source.strip()
            for p in Policy.objects.filter(type=Policy.Type.CEDAR, is_active=True)
        ).strip()
        self._last_refresh_ts = time.monotonic()

    @property
    def all_policies_concatenated(self):
        with self._lock:
            self._refresh()
            return self._concatenated_policies


# used for the tests
zentral_policies_sync = os.environ.get("ZENTRAL_POLICIES_SYNC", "1") == "1"


policies_cache = PoliciesCache(with_sync=zentral_policies_sync)


def _serialize_entity(entity: Entity, collected_entities: dict) -> None:
    key = (entity.type, entity.id)
    if key not in collected_entities:
        serialized_entity = {
            "uid": {"type": entity.full_type, "id": entity.id},
            "attrs": {},
            "parents": []
        }
        collected_entities[key] = serialized_entity
        for parent in entity.parents:
            _serialize_entity(parent, collected_entities)
            serialized_entity["parents"].append({"type": parent.full_type, "id": parent.id})


def _serialize_requests_entities(requests: list[Request]) -> list:
    collected_entities = {}
    for request in requests:
        for entity in (request.principal, request.action, request.resource):
            _serialize_entity(entity, collected_entities)
    return list(collected_entities.values())


def _serialize_request(request: Request, correlation_id: Optional[str] = None) -> dict:
    data = {
        "principal": str(request.principal),
        "action": str(request.action),
        "resource": str(request.resource),
        "context": request.context,
    }
    if correlation_id:
        data["correlation_id"] = correlation_id
    return data


def authorize_request(request: Request) -> None:
    cedar_result = is_authorized(
        _serialize_request(request),
        policies_cache.all_policies_concatenated,
        _serialize_requests_entities([request]),
    )
    request.is_authorized = cedar_result.allowed


def authorize_requests(requests: list[Request]) -> None:
    if not requests:
        return
    req_dict = {r.correlation_id: r for r in requests}
    for cedar_result in is_authorized_batch(
        (_serialize_request(r, correlation_id=r.correlation_id) for r in requests),
        policies_cache.all_policies_concatenated,
        _serialize_requests_entities(requests),
    ):
        req_dict[cedar_result.correlation_id].is_authorized = cedar_result.allowed
