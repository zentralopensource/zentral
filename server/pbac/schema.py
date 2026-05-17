"""Backend-neutral schema IR generator.

Walks the PBAC engine's namespaces / entity_types / action_groups / actions
and produces a structured schema description that any backend renderer
(server/pbac/cedar.py today, server/pbac/rego.py in the future) can
consume.

Nothing in this module imports cedarpy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .types import AppliesTo, AttrSpec


@dataclass(frozen=True)
class EntityTypeIR:
    name: str
    namespace_id: Optional[str]
    # Qualified parent names (e.g. "Role", "Inventory::MetaBusinessUnit").
    parents: tuple
    # Attribute name -> AttrSpec
    attrs: dict

    @property
    def qualified_name(self) -> str:
        if self.namespace_id:
            return f"{self.namespace_id}::{self.name}"
        return self.name


@dataclass(frozen=True)
class AppliesToIR:
    # Qualified entity-type names.
    principals: tuple
    resources: tuple
    # None = "no context declared". Empty dict = "context explicitly empty".
    context: Optional[dict]


@dataclass(frozen=True)
class ActionIR:
    """An Action — concrete or group.

    Action groups are represented as actions with ``applies_to=None`` and
    no ``member_of`` (they're just the Cedar entities other actions point
    to).
    """
    id: str
    namespace_id: Optional[str]
    # List of (id, namespace_id|None) tuples; the action groups this
    # action belongs to.
    member_of: tuple
    # Optional AppliesToIR. ``None`` means this is an action group, not a
    # concrete action.
    applies_to: Optional[AppliesToIR]


@dataclass
class NamespaceIR:
    id: Optional[str]
    # name -> EntityTypeIR
    entity_types: dict = field(default_factory=dict)
    # id -> ActionIR
    actions: dict = field(default_factory=dict)


@dataclass
class SchemaIR:
    # namespace_id (or None for the global namespace) -> NamespaceIR
    namespaces: dict = field(default_factory=dict)


def build_schema_ir(engine) -> SchemaIR:
    """Build a SchemaIR from the engine's current registration state.

    Pure function: walks engine.{namespaces, entity_types, action_groups,
    actions} once. Safe to call multiple times — output depends only on
    engine state.
    """
    ir = SchemaIR()

    def _ns(ns_id):
        if ns_id not in ir.namespaces:
            ir.namespaces[ns_id] = NamespaceIR(id=ns_id)
        return ir.namespaces[ns_id]

    # Seed all namespaces the engine knows about, plus the global None.
    _ns(None)
    for ns_id in engine.namespaces:
        _ns(ns_id)

    # Entity types
    for (et_name, ns_id), et in engine.entity_types.items():
        _ns(ns_id).entity_types[et_name] = EntityTypeIR(
            name=et_name,
            namespace_id=ns_id,
            parents=tuple(p.qualified_name for p in et.parents),
            attrs=dict(et.attrs),
        )

    # Action groups (Cedar Actions with no appliesTo)
    for (ag_id, ns_id), ag in engine.action_groups.items():
        _ns(ns_id).actions[ag_id] = ActionIR(
            id=ag_id,
            namespace_id=ns_id,
            member_of=(),
            applies_to=None,
        )

    # Concrete actions
    for (action_id, ns_id), action in engine.actions.items():
        applies_to: AppliesTo = action.applies_to
        ns = _ns(ns_id)
        ns.actions[action_id] = ActionIR(
            id=action_id,
            namespace_id=ns_id,
            member_of=tuple(
                (p.id, p.namespace.id if p.namespace else None)
                for p in action.parents
            ),
            applies_to=AppliesToIR(
                principals=tuple(p.qualified_name for p in applies_to.principals),
                resources=tuple(r.qualified_name for r in applies_to.resources),
                context=dict(applies_to.context) if applies_to.context is not None else None,
            ),
        )

    return ir


__all__ = ["AppliesToIR", "ActionIR", "EntityTypeIR", "NamespaceIR", "SchemaIR", "build_schema_ir"]
