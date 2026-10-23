"""Scope a list with one SQL filter, not with one decision for each row.

Cedar evaluates the policies for a request without a resource. It returns the policies that it cannot decide
without the resource. This module writes them as a Django Q.

It writes only a small part of the policy language: the expressions that cannot error on the declared types.
Cedar skips a policy that errors, and the SQL filter must give the same rows. For all other expressions, it
returns None, and the caller makes one decision for each row.
"""
from django.core.exceptions import ValidationError
from django.db.models import Q

from .engine import engine
from .entities import Principal, Request
from .types import _PY_TYPE_MAP, EntityType, PrimitiveType


class Unsupported(Exception):
    pass


_UNKNOWN_RESOURCE = {"unknown": [{"Value": "resource"}]}
_ALL = {"op": "All"}
_POLICY_KEYS = {"effect", "principal", "action", "resource", "conditions", "annotations"}
# The deepest nesting of conditions that this module writes. It and Django recurse on the nesting, so a deeper
# policy gives None. A chain of one operator, such as a || b || c, is one level.
_MAX_DEPTH = 32


def values_q(lookup, values):
    """A Q for the rows with one of the values, or False when no value is left."""
    # no text column has a NUL, and psycopg2 refuses one in a parameter
    values = list(dict.fromkeys(value for value in values if not (isinstance(value, str) and "\x00" in value)))
    if not values:
        return False
    if len(values) == 1:
        return Q(**{lookup: values[0]})
    return Q(**{f"{lookup}__in": values})


def id_value(field, entity_id):
    """The value of the field for an entity id, or None when no row can have this id."""
    try:
        value = field.to_python(entity_id)
    except ValidationError:
        return None
    # Cedar compares the ids as strings: "01" is not "1"
    if str(value) != entity_id:
        return None
    return value


class SQLMap:
    """The columns of a list, for the questions that a policy can ask about its resource type.

    entities: for the resource type and its ancestor types, the lookup of the primary key of the entity, or a
    function that gives a Q, True or False for a list of entity ids: the rows in one of these entities. An id
    that is not the string of a primary key, for example the URL-safe serial number of a machine, needs a
    function.

    attributes: for each attribute path, for example "job.kind", the lookup of its column. For an entity
    attribute, the lookup of the primary key of the entity.
    """

    def __init__(self, model, resource_type, entities, attributes):
        self.model = model
        self.resource_type = resource_type
        # the types of the entities that a row is in: its own type too
        self.ancestor_types = set()
        types = [resource_type]
        while types:
            entity_type = types.pop()
            if entity_type.qualified_name not in self.ancestor_types:
                self.ancestor_types.add(entity_type.qualified_name)
                types.extend(entity_type.parents)
        self.id_fields = {}
        self.entities = {}
        for entity_type, lookup in entities.items():
            if entity_type.qualified_name not in self.ancestor_types:
                raise ValueError(f"{entity_type.qualified_name} is not an ancestor type "
                                 f"of {resource_type.qualified_name}")
            if not callable(lookup):
                self.id_fields[lookup] = self._id_field(lookup)
            self.entities[entity_type.qualified_name] = lookup
        self.attributes = {}
        for path, lookup in attributes.items():
            attribute_type = self._attribute_type(path)
            if isinstance(attribute_type, EntityType):
                self.id_fields[lookup] = self._id_field(lookup)
            self.attributes[tuple(path.split("."))] = (lookup, attribute_type)

    def _attribute_type(self, path):
        attribute_type = self.resource_type
        for name in path.split("."):
            spec = attribute_type.attrs.get(name) if isinstance(attribute_type, EntityType) else None
            # Cedar errors on an optional attribute that is not there
            if spec is None or not spec.required:
                raise ValueError(f"{path} is not a path of required attributes "
                                 f"of {self.resource_type.qualified_name}")
            attribute_type = spec.type
        if not isinstance(attribute_type, (EntityType, PrimitiveType)):
            raise ValueError(f"{path} is not an entity or a primitive")
        return attribute_type

    def _id_field(self, lookup):
        field = None
        model = self.model
        for name in lookup.split("__"):
            if field is not None:
                model = field.related_model
            field = model._meta.pk if name == "pk" else model._meta.get_field(name)
        if field.is_relation:
            field = field.target_field
        # the builders give an entity the string of its primary key as id, and _id_q compares with that string
        if not field.primary_key:
            raise ValueError(f"{lookup} is not the primary key of an entity")
        return field

    def _id_q(self, lookup, entity_ids):
        field = self.id_fields[lookup]
        values = (id_value(field, entity_id) for entity_id in entity_ids)
        return values_q(lookup, (value for value in values if value is not None))

    def _entity_q(self, entity_type, entity_ids):
        try:
            lookup = self.entities[entity_type]
        except KeyError:
            raise Unsupported
        if callable(lookup):
            return lookup(entity_ids)
        return self._id_q(lookup, entity_ids)

    def resource_in(self, entity_type, entity_ids):
        if entity_type not in self.ancestor_types:
            return False
        return self._entity_q(entity_type, entity_ids)

    def resource_equal(self, literal_type, value):
        if literal_type != self.resource_type.qualified_name:
            return False
        return self._entity_q(literal_type, [value])

    def resource_is(self, entity_type):
        return entity_type == self.resource_type.qualified_name

    def attribute_equal(self, path, literal_type, value):
        try:
            lookup, attribute_type = self.attributes[path]
        except KeyError:
            raise Unsupported
        if isinstance(attribute_type, EntityType):
            if literal_type != attribute_type.qualified_name:
                return False
            return self._id_q(lookup, [value])
        if literal_type != attribute_type:
            return False
        return values_q(lookup, [value])


# The JSON policy format of Cedar. An expression is a dict with one key, the operator.


def _node(expr):
    if isinstance(expr, dict) and len(expr) == 1:
        return next(iter(expr.items()))
    raise Unsupported


def _operands(arg, *names):
    try:
        return [arg[name] for name in names]
    except (KeyError, TypeError):
        raise Unsupported


def _literal(expr):
    """The type and the value of a literal. For an entity: its type name and its id."""
    op, value = _node(expr)
    if op == "Value":
        literal_type = _PY_TYPE_MAP.get(type(value))
        if literal_type is not None:
            return literal_type, value
        if isinstance(value, dict) and set(value) == {"__entity"}:
            entity_type, entity_id = _operands(value["__entity"], "type", "id")
            if isinstance(entity_type, str) and isinstance(entity_id, str):
                return entity_type, entity_id
    raise Unsupported


def _path(expr):
    """The attribute names of resource.a.b, an empty tuple for the resource, None for other expressions."""
    names = []
    while expr != _UNKNOWN_RESOURCE:
        op, arg = _node(expr)
        if op != ".":
            return None
        expr, name = _operands(arg, "left", "attr")
        if not isinstance(name, str):
            raise Unsupported
        names.insert(0, name)
    return tuple(names)


def _and(left, right):
    if left is False or right is False:
        return False
    if left is True:
        return right
    if right is True:
        return left
    return left & right


def _or(left, right):
    if left is True or right is True:
        return True
    if left is False:
        return right
    if right is False:
        return left
    return left | right


def _not(value):
    if isinstance(value, bool):
        return not value
    return ~value


def _equal(left, right, sql_map):
    path = _path(left)
    if path is None:
        left, right = right, left
        path = _path(left)
        if path is None:
            raise Unsupported
    literal_type, value = _literal(right)
    if path:
        return sql_map.attribute_equal(path, literal_type, value)
    return sql_map.resource_equal(literal_type, value)


def _chain(op, expr):
    """The operands of a || b || c, in order, without recursion: Cedar nests a chain as deep as it is long."""
    operands = []
    pending = [expr]
    while pending:
        expr = pending.pop()
        node_op, arg = _node(expr)
        if node_op == op:
            pending.extend(reversed(_operands(arg, "left", "right")))
        else:
            operands.append(expr)
    return operands


def _resource_in(elements, sql_map):
    # one Q for each entity type: a set of meta business units is one EXISTS, not one EXISTS for each unit
    entity_ids = {}
    for element in elements:
        literal_type, value = _literal(element)
        # Cedar errors on in with a value that is not an entity
        if isinstance(literal_type, PrimitiveType):
            raise Unsupported
        entity_ids.setdefault(literal_type, []).append(value)
    result = False
    for entity_type, ids in entity_ids.items():
        result = _or(result, sql_map.resource_in(entity_type, ids))
    return result


def _boolean(expr, sql_map, depth=0):
    if depth > _MAX_DEPTH:
        raise Unsupported
    op, arg = _node(expr)
    if op == "Value":
        if isinstance(arg, bool):
            return arg
    elif op in ("&&", "||"):
        # Cedar reads a chain from the left and stops at the first operand that decides it, so the operands after
        # it can be outside the subset, for example `resource is <another type> && resource.<its attribute>`.
        # Not the operands before it: Cedar evaluates them, and they can error.
        combine, value, decided = (_and, True, False) if op == "&&" else (_or, False, True)
        for operand in _chain(op, expr):
            value = combine(value, _boolean(operand, sql_map, depth + 1))
            if value is decided:
                break
        return value
    elif op == "!":
        return _not(_boolean(_operands(arg, "arg")[0], sql_map, depth + 1))
    elif op in ("==", "!="):
        equal = _equal(*_operands(arg, "left", "right"), sql_map)
        return equal if op == "==" else _not(equal)
    elif op == "in":
        left, right = _operands(arg, "left", "right")
        if left == _UNKNOWN_RESOURCE:
            set_op, elements = _node(right)
            if set_op != "Set":
                return _resource_in([right], sql_map)
            if isinstance(elements, list):
                return _resource_in(elements, sql_map)
    elif op == "is":
        # Cedar gives `is … in …` as an is and an in. An in in the is would be lost.
        if isinstance(arg, dict) and set(arg) == {"left", "entity_type"} and arg["left"] == _UNKNOWN_RESOURCE:
            entity_type = arg["entity_type"]
            if isinstance(entity_type, str):
                return sql_map.resource_is(entity_type)
    raise Unsupported


def _policy(policy, sql_map):
    if not isinstance(policy, dict) or not set(policy) <= _POLICY_KEYS:
        raise Unsupported
    # the request has the principal and the action, so Cedar decides their scopes
    if any(policy.get(scope) != _ALL for scope in ("principal", "action", "resource")):
        raise Unsupported
    effect, conditions = _operands(policy, "effect", "conditions")
    if not isinstance(conditions, list):
        raise Unsupported
    value = True
    for condition in conditions:
        kind, body = _operands(condition, "kind", "body")
        if kind == "when":
            value = _and(value, _boolean(body, sql_map))
        elif kind == "unless":
            value = _and(value, _not(_boolean(body, sql_map)))
        else:
            raise Unsupported
    return effect, value


def compile_policies(policies, sql_map):
    """A Q for the rows that the policies allow, True for all the rows, False for no row, or None."""
    permits = forbids = False
    try:
        if not isinstance(policies, dict):
            raise Unsupported
        for policy in policies.values():
            effect, value = _policy(policy, sql_map)
            if effect == "permit":
                permits = _or(permits, value)
            elif effect == "forbid":
                forbids = _or(forbids, value)
            else:
                raise Unsupported
    except Unsupported:
        return None
    return _and(permits, _not(forbids))


def _has_context(action):
    # Cedar evaluates the list with an empty context, so a forbid that reads the context of a row would not apply
    return action.applies_to is not None and bool(action.applies_to.context)


def scope_queryset(user_obj, action, queryset, sql_map):
    """The rows of the queryset that the user can see with the action, with one SQL filter.

    Return None when a policy has an expression that this module cannot write as SQL. The caller then makes
    one decision for each row.
    """
    if _has_context(action):
        raise ValueError("An action with a context needs one decision for each row")
    policies = engine.undecided_policies(Request(Principal.from_user(user_obj), action, None))
    if not isinstance(policies, bool):
        policies = compile_policies(policies, sql_map)
    if policies is None:
        return None
    if policies is True:
        return queryset
    if policies is False:
        return queryset.none()
    return queryset.filter(policies)


def visible_rows(user_obj, request_class, queryset):
    """The rows of the queryset that the user can see with request_class.pbac_action, as a queryset.

    One SQL filter with request_class.sql_map when the action has no context and the policies allow it. Else
    one decision for each row: request_class.requests_for_rows(user_obj, rows) gives the requests, with the
    context of each row, and request_class.row_relations names the relations that the requests read.
    """
    action = request_class.pbac_action
    if not _has_context(action):
        scoped_queryset = scope_queryset(user_obj, action, queryset, request_class.sql_map)
        if scoped_queryset is not None:
            return scoped_queryset
    # all the rows, before the page: a page cut first drops rows that the user can see
    rows = list(queryset.select_related(*request_class.row_relations).prefetch_related(None))
    requests = request_class.requests_for_rows(user_obj, rows)
    engine.authorize_requests(requests)
    return queryset.filter(pk__in=[row.pk for row, request in zip(rows, requests) if request.is_authorized])
