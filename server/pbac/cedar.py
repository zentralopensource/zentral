import logging
import os
import threading
import time
from typing import Optional
import weakref

from cedarpy import Decision, is_authorized, is_authorized_batch, is_authorized_partial, PolicySet

from base.notifier import notifier
from .entities import Entity, Request
from .schema import ActionIR, AppliesToIR, EntityTypeIR, SchemaIR
from .types import AttrSpec, EntityType, ExtensionType, PrimitiveType, RecordOf, SetOf, format_type


logger = logging.getLogger("zentral.pbac.cedar")


class PoliciesCache:
    # Fallback for missed notifier notifications
    max_age_seconds = 300

    def __init__(self, with_sync=False):
        self._policy_set = None
        self._last_refresh_ts = None
        self._lock = threading.Lock()
        self.with_sync = with_sync  # if False, every read will hit the DB
        self._sync_started = False

    def clear(self, *args, **kwargs):
        with self._lock:
            self._policy_set = None
            self._last_refresh_ts = None
            logger.debug("Policies cache sync cleared")

    def _start_sync(self):
        if self.with_sync:
            if not self._sync_started:
                # Currently, a weakref doesn't buy us much since this class is only use as a module level singleton,
                # but it might be used differently in the future.
                notifier.add_callback("policies.change", weakref.WeakMethod(self.clear))
                logger.debug("Policies cache sync started")
                self._sync_started = True

    def _refresh(self):
        self._start_sync()
        if (
            self.with_sync
            and self._policy_set is not None
            and self._last_refresh_ts is not None
            and time.monotonic() - self._last_refresh_ts <= self.max_age_seconds
        ):
            logger.debug("Policies cache up to date")
            return
        logger.debug("Refresh policies cache")
        from accounts.models import Policy  # TODO reorganize to fix circular import?
        concatenated_policies = "\n".join(
            p.source.strip()
            for p in Policy.objects.filter(type=Policy.Type.CEDAR, is_active=True)
        ).strip()
        # Policies stored in the DB are known-good so this should never raise an error
        self._policy_set = PolicySet.from_str(concatenated_policies)
        self._last_refresh_ts = time.monotonic()

    @property
    def policy_set(self):
        with self._lock:
            # It might trigger a DB request, but we are OK because the DB query is cheap.
            # Also, the lock is not shared across the application.
            self._refresh()
            return self._policy_set


# used for the tests
zentral_policies_sync = os.environ.get("ZENTRAL_POLICIES_SYNC", "1") == "1"


policies_cache = PoliciesCache(with_sync=zentral_policies_sync)


def _serialize_value(value, collected_entities: dict):
    """Render a value for Cedar, collecting every entity it points at, however deeply.

    An entity attribute or a context key may itself be an Entity — a one-time job pointing at the job
    it runs, a create request naming the job it is about — which Cedar reads as a reference. The
    referenced entity has to be in the slice as well: Cedar resolves ``context.job.kind`` against the
    store, and an entity that is not there fails the dereference. That failure turns a forbid into an
    allow with nothing but a diagnostic to show for it, so the walk is what keeps an entity-valued
    declaration from being quietly unenforceable.
    """
    if isinstance(value, Entity):
        _serialize_entity(value, collected_entities)
        return {"__entity": {"type": value.full_type, "id": value.id}}
    if isinstance(value, dict):
        return {k: _serialize_value(v, collected_entities) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_serialize_value(v, collected_entities) for v in value]
    return value


def _serialize_entity(entity: Entity, collected_entities: dict) -> None:
    key = (entity.full_type, entity.id)
    if key not in collected_entities:
        serialized_entity = {
            "uid": {"type": entity.full_type, "id": entity.id},
            "attrs": {},
            "parents": []
        }
        # in the dict before the attributes are walked, so an entity that points back at this one
        # does not recurse forever
        collected_entities[key] = serialized_entity
        serialized_entity["attrs"] = _serialize_value(entity.attrs, collected_entities)
        for parent in entity.parents:
            _serialize_entity(parent, collected_entities)
            serialized_entity["parents"].append({"type": parent.full_type, "id": parent.id})


def _serialize_requests_entities(requests: list[Request]) -> list:
    collected_entities = {}
    for request in requests:
        for entity in (request.principal, request.action, request.resource):
            _serialize_entity(entity, collected_entities)
        # the context too: an entity named there is dereferenced against the same store
        _serialize_value(request.context, collected_entities)
    return list(collected_entities.values())


def _serialize_request(request: Request, correlation_id: Optional[str] = None) -> dict:
    data = {
        "principal": str(request.principal),
        "action": str(request.action),
        "resource": str(request.resource),
        # None, not {}: is_authorized_partial reads an absent context as unknown and residualizes,
        # where an empty one is a record with no attributes and a policy reading one fails on it.
        # The collector is thrown away here — _serialize_requests_entities does the collecting — but
        # the rendering is the same, so an Entity in the context reaches Cedar as a reference.
        "context": None if request.unknown_context else _serialize_value(request.context, {}),
    }
    if correlation_id:
        data["correlation_id"] = correlation_id
    return data


def authorize_request(request: Request) -> None:
    # Note: we deliberately do not pass the engine schema here. Schema
    # validation happens once at policy-write time (Policy.clean calls
    # cedarpy.validate_policies against engine.cedar_schema_json) so the
    # policies stored in the DB are known-good. Re-validating per request
    # would add ~16ms / call (cedarpy re-parses the ~120KB schema on every
    # is_authorized call), which dominates view rendering when there are
    # multiple has_perm / has_module_perms checks. For the same reason the
    # policies are pre-parsed into a PolicySet by policies_cache, so
    # is_authorized doesn't re-parse them on every call either.
    cedar_result = is_authorized(
        _serialize_request(request),
        policies_cache.policy_set,
        _serialize_requests_entities([request]),
    )
    request.is_authorized = cedar_result.allowed


def authorize_request_preview(request: Request) -> None:
    """Answer a request whose context is not complete yet, by partial evaluation.

    This is NOT a final authorization decision, and cedarpy says so itself: an Allow here holds only
    for the unknowns that were supplied. Only Deny is definitive — no policy can permit the request
    whatever the missing context turns out to be. Allow and NoDecision both mean "could be permitted",
    which is the right answer for a view asking whether to offer an action at all; the real decision
    is made later, on a request that carries the whole context.
    """
    cedar_result = is_authorized_partial(
        _serialize_request(request),
        policies_cache.policy_set,
        _serialize_requests_entities([request]),
    )
    request.is_authorized = cedar_result.decision != Decision.Deny


def authorize_requests(requests: list[Request]) -> None:
    if not requests:
        return
    req_dict = {r.correlation_id: r for r in requests}
    for cedar_result in is_authorized_batch(
        (_serialize_request(r, correlation_id=r.correlation_id) for r in requests),
        policies_cache.policy_set,
        _serialize_requests_entities(requests),
    ):
        req_dict[cedar_result.correlation_id].is_authorized = cedar_result.allowed


# Cedar schema rendering
#
# Two renderers, both pure functions over a SchemaIR:
#
#   render_schema_json(ir) -> dict
#       The JSON-schema form cedarpy expects via the ``schema=`` argument
#       to ``is_authorized`` and ``validate_policies``. Uses Cedar's JSON
#       spelling: "Boolean"/"Long"/"String", "principalTypes"/"resourceTypes",
#       and the empty string "" for the global namespace.
#
#   render_schema_human(ir) -> str
#       The human-readable schema form Cedar accepts. Mainly for the
#       pbac_dump_schema management command and ad-hoc debugging — uses
#       Cedar's policy-syntax spelling: "Bool"/"Long"/"String",
#       "principal"/"resource", explicit "namespace X { ... }" blocks.


# The JSON form is the only place Cedar's spelling of the primitives
# differs from the IR's own; everything else goes through
# pbac.types.format_type.

_JSON_PRIMITIVES = {
    PrimitiveType.BOOL: "Boolean",
    PrimitiveType.LONG: "Long",
    PrimitiveType.STRING: "String",
}


def _attr_to_json(attr: AttrSpec) -> dict:
    t = attr.type
    if isinstance(t, PrimitiveType):
        out = {"type": _JSON_PRIMITIVES[t]}
    elif isinstance(t, ExtensionType):
        out = {"type": "Extension", "name": t.value}
    elif isinstance(t, EntityType):
        out = {"type": "Entity", "name": t.qualified_name}
    elif isinstance(t, SetOf):
        # Cedar's Set element is itself an attr-shaped object.
        out = {"type": "Set", "element": _attr_to_json(AttrSpec(t.inner))}
    elif isinstance(t, RecordOf):
        out = {
            "type": "Record",
            "attributes": {n: _attr_to_json(a) for n, a in t.fields.items()},
        }
    else:
        raise TypeError(f"Unsupported attribute type {t!r}")
    if not attr.required:
        out["required"] = False
    return out


def _entity_type_to_json(et: EntityTypeIR) -> dict:
    entry: dict = {}
    if et.parents:
        entry["memberOfTypes"] = list(et.parents)
    if et.attrs:
        entry["shape"] = {
            "type": "Record",
            "attributes": {n: _attr_to_json(a) for n, a in et.attrs.items()},
        }
    return entry


def _action_to_json(action: ActionIR) -> dict:
    entry: dict = {}
    if action.member_of:
        # Reference action groups by id alone. cedarpy resolves
        # `{"id": "AdminActions"}` inside namespace block ``Inventory`` to
        # ``Inventory::Action::"AdminActions"``, and a top-level
        # ``{"id": "GlobalAdminActions"}`` to ``Action::"GlobalAdminActions"``.
        entry["memberOf"] = [{"id": ag_id} for ag_id, _ in action.member_of]
    if action.applies_to is not None:
        applies_to: AppliesToIR = action.applies_to
        appt: dict = {
            "principalTypes": list(applies_to.principals),
            "resourceTypes": list(applies_to.resources),
        }
        if applies_to.context is not None:
            appt["context"] = {
                "type": "Record",
                "attributes": {n: _attr_to_json(a) for n, a in applies_to.context.items()},
            }
        entry["appliesTo"] = appt
    return entry


def render_schema_json(ir: SchemaIR) -> dict:
    """Render a SchemaIR into the Cedar JSON schema format.

    Every emitted namespace contains both ``entityTypes`` and ``actions``
    keys, even when one is empty — cedarpy treats a missing key as a parse
    error.
    """
    out = {}
    for ns_id, ns in ir.namespaces.items():
        if not ns.entity_types and not ns.actions:
            continue
        # Cedar uses "" as the key for the global namespace.
        ns_key = ns_id if ns_id is not None else ""
        out[ns_key] = {
            "entityTypes": {n: _entity_type_to_json(et) for n, et in ns.entity_types.items()},
            "actions": {i: _action_to_json(a) for i, a in ns.actions.items()},
        }
    return out


# Human-readable rendering.

def _optional_marker(attr: AttrSpec) -> str:
    return "" if attr.required else "?"


def _format_attr_record(record: dict, indent: str) -> str:
    """Format a {name: AttrSpec} dict as a Cedar record body."""
    if not record:
        return "{}"
    lines = []
    for name, attr in record.items():
        lines.append(f'{indent}  {name}{_optional_marker(attr)}: {format_type(attr.type)}')
    return "{\n" + ",\n".join(lines) + f"\n{indent}}}"


def _entity_type_to_human(et: EntityTypeIR, indent: str) -> str:
    head = f"{indent}entity {et.name}"
    if et.parents:
        head += " in [" + ", ".join(et.parents) + "]"
    if et.attrs:
        head += " = " + _format_attr_record(et.attrs, indent)
    return head + ";"


def _action_group_ref_human(action_ns_id, ag_id, ag_ns_id) -> str:
    if ag_ns_id == action_ns_id:
        # Same namespace as the referrer — bare form.
        return f'"{ag_id}"'
    if ag_ns_id is None:
        # Cross-namespace global reference.
        return f'Action::"{ag_id}"'
    # Different non-global namespace.
    return f'{ag_ns_id}::Action::"{ag_id}"'


def _action_to_human(action: ActionIR, indent: str) -> str:
    head = f"{indent}action {action.id!r}".replace("'", '"')
    if action.member_of:
        head += " in [" + ", ".join(
            _action_group_ref_human(action.namespace_id, ag_id, ag_ns)
            for ag_id, ag_ns in action.member_of
        ) + "]"
    if action.applies_to is None:
        return head + ";"
    appt: AppliesToIR = action.applies_to
    parts = [
        f"{indent}  principal: [" + ", ".join(appt.principals) + "]",
        f"{indent}  resource: [" + ", ".join(appt.resources) + "]",
    ]
    if appt.context is not None:
        parts.append(f"{indent}  context: " + _format_attr_record(appt.context, indent + "  "))
    body = ",\n".join(parts)
    return head + " appliesTo {\n" + body + f"\n{indent}}};"


def render_schema_human(ir: SchemaIR) -> str:
    """Render a SchemaIR into Cedar's human-readable schema syntax.

    Primarily for ops/debugging via the pbac_dump_schema management
    command. The JSON form is what we feed to cedarpy.
    """
    blocks = []
    # Global namespace first (no wrapping `namespace { ... }`).
    global_ns = ir.namespaces.get(None)
    if global_ns is not None and (global_ns.entity_types or global_ns.actions):
        for et in global_ns.entity_types.values():
            blocks.append(_entity_type_to_human(et, ""))
        for action in global_ns.actions.values():
            blocks.append(_action_to_human(action, ""))
    # Namespaced blocks.
    for ns_id, ns in ir.namespaces.items():
        if ns_id is None:
            continue
        if not ns.entity_types and not ns.actions:
            continue
        inner = []
        for et in ns.entity_types.values():
            inner.append(_entity_type_to_human(et, "  "))
        for action in ns.actions.values():
            inner.append(_action_to_human(action, "  "))
        blocks.append(f"namespace {ns_id} {{\n" + "\n".join(inner) + "\n}")
    return "\n\n".join(blocks) + ("\n" if blocks else "")
