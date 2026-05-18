"""Backend-neutral type IR for the PBAC engine.

These types describe what an Action accepts (its principal types, resource
types, and optional context shape) and what attributes/parent relationships
each entity type has.

Nothing in this module imports cedarpy or any other authorization backend.
The naming follows Cedar's human-readable schema conventions where they
happen to be a sensible default (`Bool`/`Long`/`String`), but the IR itself
makes no commitment to Cedar.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


# Primitive and extension types


class PrimitiveType(Enum):
    BOOL = "Bool"
    LONG = "Long"
    STRING = "String"


class ExtensionType(Enum):
    DECIMAL = "decimal"
    IPADDR = "ipaddr"
    DATETIME = "datetime"
    DURATION = "duration"


# Entity types (type-level, distinct from pbac.entities.Entity instances)


class EntityType:
    """Type-level entity descriptor.

    Distinct from ``pbac.entities.Entity`` which models a runtime instance.
    The engine keeps a registry of EntityType per (namespace, name); contrib
    modules declare types once at import time.
    """

    def __init__(self, name, namespace=None, attrs=None, parents=()):
        self.name = name
        self.namespace = namespace                # pbac.entities.Namespace | None
        self.attrs = dict(attrs or {})            # dict[str, AttrSpec]
        self.parents = tuple(parents)             # tuple[EntityType, ...]

    @property
    def qualified_name(self):
        if self.namespace:
            return f"{self.namespace}::{self.name}"
        return self.name

    def __repr__(self):
        return f"{self.__class__.__name__} <{self.qualified_name}>"


class PrincipalType(EntityType):
    pass


class ResourceType(EntityType):
    pass


# Container types


@dataclass(frozen=True)
class SetOf:
    inner: "TypeRef"


@dataclass(frozen=True)
class RecordOf:
    # dict[str, AttrSpec]; left untyped here because AttrSpec is defined below
    fields: dict


# A type reference is any of:
#   - PrimitiveType / ExtensionType (enum members)
#   - an EntityType (or subclass)
#   - SetOf(...) or RecordOf(...) wrapping any of the above
TypeRef = Union[PrimitiveType, ExtensionType, EntityType, SetOf, RecordOf]


# AttrSpec with Python-type coercion


# Hash-equality lookup table. `bool` and `int` are distinct dict keys, so
# `bool` resolves to BOOL — no ordering footgun.
_PY_TYPE_MAP = {
    bool: PrimitiveType.BOOL,
    int:  PrimitiveType.LONG,
    str:  PrimitiveType.STRING,
}


def _coerce_type(t):
    """Accept Python builtins (`bool`/`int`/`str`) as sugar for PrimitiveType.

    Anything else must already be a TypeRef (PrimitiveType, ExtensionType,
    EntityType, SetOf, RecordOf).
    """
    if isinstance(t, (PrimitiveType, ExtensionType, SetOf, RecordOf, EntityType)):
        return t
    if t in _PY_TYPE_MAP:
        return _PY_TYPE_MAP[t]
    raise TypeError(f"Unsupported attribute type {t!r}")


@dataclass(frozen=True)
class AttrSpec:
    type: TypeRef
    required: bool = True

    def __init__(self, type, required=True):
        # Frozen dataclass; coerce via object.__setattr__.
        object.__setattr__(self, "type", _coerce_type(type))
        object.__setattr__(self, "required", required)


# AppliesTo


@dataclass(frozen=True)
class AppliesTo:
    """Per-action declaration: which principals/resources, plus context shape.

    ``context=None`` means "no context declared". ``context={}`` means
    "context is explicitly empty". Cedar's human-readable schema renders
    both the same way; only the JSON form distinguishes them. The IR keeps
    the distinction so renderers can emit the correct form.
    """
    principals: tuple
    resources: tuple
    context: Optional[dict] = None

    def __post_init__(self):
        if not isinstance(self.principals, tuple):
            object.__setattr__(self, "principals", tuple(self.principals))
        if not isinstance(self.resources, tuple):
            object.__setattr__(self, "resources", tuple(self.resources))


# Built-ins


# Common ancestor type used as a parent of User and ServiceAccount, mirroring
# how Principal.from_user serialises group membership.
ROLE = EntityType("Role")

USER = PrincipalType(
    "User",
    attrs={"is_superuser": AttrSpec(bool)},
    parents=(ROLE,),
)

SERVICE_ACCOUNT = PrincipalType(
    "ServiceAccount",
    parents=(ROLE,),
)

# The catch-all resource used by every auto-registered legacy-perm action.
# Backed at the instance level by ``Resource("System", "any")``; the type
# itself carries no attributes.
SYSTEM = ResourceType("System")


# The AppliesTo every auto-registered legacy-perm action gets. Explicit
# empty ``context`` so the JSON schema renderer can distinguish "no context"
# from "not declared".
LEGACY_PERM_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(SYSTEM,),
    context={},
)
