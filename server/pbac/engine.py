from enum import Enum
from functools import cached_property
import logging
from typing import Optional

from django.apps.config import AppConfig
from django.contrib.auth import get_permission_codename
from django.db.models.base import ModelBase

from .cedar import authorize_request, authorize_requests, render_schema_json
from .entities import Action, ActionGroup, Namespace, Principal, Request, Resource
from .schema import build_schema_ir
from .types import (
    AppliesTo,
    EntityType,
    LEGACY_PERM_APPLIES_TO,
    ROLE,
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
)


logger = logging.getLogger("zentral.pbac.engine")


class ActionGroupBasename(Enum):
    ADMIN = "Admin"
    USER = "User"
    VIEWER = "Viewer"

    def __str__(self):
        return self.value


class ActionRegistrationConflict(ValueError):
    pass


class EntityTypeConflict(ValueError):
    pass


class Engine:
    def __init__(self) -> None:
        self.namespaces = {}
        self.action_groups = {}
        self.actions = {}
        # Keyed (name, namespace_id|None) to match ``actions`` and
        # ``action_groups`` (both id-first, namespace-second).
        self.entity_types = {}
        self.module_legacy_perm_actions = {}
        self.legacy_perm_actions = {}
        self.system_any_resource = Resource("System", "any")
        # Register built-in entity types so the schema generator (PR C) sees
        # User/ServiceAccount/Role/System without anyone having to call
        # register_entity_type explicitly.
        for et in (ROLE, USER, SERVICE_ACCOUNT, SYSTEM):
            self.register_entity_type(et)

    # Entity types

    def register_entity_type(self, et: EntityType) -> EntityType:
        """Register (or idempotently re-register) an EntityType.

        Parents are auto-registered. Re-registering with the same EntityType
        instance is a no-op. Re-registering with a different instance under
        the same (namespace, name) raises EntityTypeConflict — entity types
        are global declarations and must be unique.
        """
        key = (et.name, et.namespace.id if et.namespace else None)
        existing = self.entity_types.get(key)
        if existing is None:
            self.entity_types[key] = et
            for parent in et.parents:
                self.register_entity_type(parent)
            return et
        if existing is et:
            return existing
        raise EntityTypeConflict(
            f"Entity type {et.qualified_name!r} already registered with a different definition "
            f"(existing={existing!r}, new={et!r})"
        )

    def get_namespace(self, id: str) -> Namespace:
        if id not in self.namespaces:
            self.namespaces[id] = Namespace(id)
        return self.namespaces[id]

    def get_action_group(self, basename: ActionGroupBasename, namespace: Optional[Namespace] = None) -> ActionGroup:
        # The id differs depending on whether the group is namespace-scoped
        # or global, so the two coexist in a Cedar schema:
        #
        #   Inventory::Action::"AdminActions"   <- namespace-scoped
        #   Action::"GlobalAdminActions"        <- global, all namespaces
        #
        # Cedar enforces global uniqueness of action ids across all
        # namespaces; without the "Global" prefix the global group would
        # "illegally shadow" each namespace-scoped one with the same id.
        if namespace is None:
            id = f"Global{basename}Actions"
        else:
            id = f"{basename}Actions"
        key = (id, namespace.id if namespace else None)
        if key not in self.action_groups:
            self.action_groups[key] = ActionGroup(id, namespace)
        return self.action_groups[key]

    def _build_action_groups(
        self,
        namespace: Namespace,
        group_basenames: Optional[list[ActionGroupBasename]],
    ) -> list[ActionGroup]:
        groups = []
        for group_basename in group_basenames or ():
            # namespace-scoped action group
            groups.append(self.get_action_group(group_basename, namespace))
            # global action group
            groups.append(self.get_action_group(group_basename))
        return groups

    def register_action(
        self,
        id: str,
        namespace: Namespace,
        group_basenames: list[ActionGroupBasename],
        applies_to: AppliesTo,
        legacy_perm: Optional[str] = None,
    ) -> Action:
        """Register (or idempotently re-register) an Action.

        ``applies_to`` is required: every action must declare the principals,
        resources, and context shape it accepts, so the schema generator can
        emit a complete schema. Use LEGACY_PERM_APPLIES_TO for actions that
        are only reachable via the legacy-perm path.

        ``legacy_perm`` is the optional Django-perm string (e.g.
        ``"inventory.add_machinetag"``) that maps to this action via
        ``ZentralBackend.has_perm``. It's intended to be retired once every
        view uses PBACViewMixin directly.

        Raises ActionRegistrationConflict if (id, namespace) is already
        registered with different action groups, a different applies_to, or
        if ``legacy_perm`` is already mapped to a different action.

        Any EntityType referenced in ``applies_to`` is auto-registered.
        """
        key = (id, namespace.id)
        new_groups = self._build_action_groups(namespace, group_basenames)
        action = self.actions.get(key)
        if action is None:
            action = Action(id, namespace, new_groups, applies_to=applies_to)
            self.actions[key] = action
        else:
            if action.parents != new_groups:
                raise ActionRegistrationConflict(
                    f"Action {action} already registered with parents {action.parents!r}; "
                    f"refusing to re-register with {new_groups!r}"
                )
            if action.applies_to != applies_to:
                raise ActionRegistrationConflict(
                    f"Action {action} already registered with applies_to {action.applies_to!r}; "
                    f"refusing to re-register with {applies_to!r}"
                )
        if legacy_perm:
            previous = self.legacy_perm_actions.get(legacy_perm)
            if previous is not None and previous is not action:
                raise ActionRegistrationConflict(
                    f"Legacy perm {legacy_perm!r} is already mapped to {previous}; "
                    f"refusing to remap to {action}"
                )
            self.legacy_perm_actions[legacy_perm] = action
        for et in (*applies_to.principals, *applies_to.resources):
            self.register_entity_type(et)
        return action

    def get_action(self, id: str, namespace: Namespace) -> Action:
        """Look up a previously registered Action. Never mutates state."""
        try:
            return self.actions[(id, namespace.id)]
        except KeyError:
            raise LookupError(
                f"Action {id!r} is not registered in namespace {namespace.id!r}"
            )

    # legacy perms

    def _get_app_config_namespace(self, app_config: AppConfig) -> Namespace:
        namespace_id = getattr(app_config, "pbac_namespace_id", app_config.name.split(".")[-1].title())
        return self.get_namespace(namespace_id)

    def _register_module_legacy_perm_action(self, app_config: AppConfig) -> None:
        namespace = self._get_app_config_namespace(app_config)
        action_id = "NOOP"
        self.module_legacy_perm_actions[app_config.label] = self.register_action(
            action_id, namespace,
            [ActionGroupBasename.VIEWER],
            LEGACY_PERM_APPLIES_TO,
        )

    def _register_model_default_legacy_perm_actions(self, app_config: AppConfig, model: ModelBase) -> None:
        namespace = self._get_app_config_namespace(app_config)
        object_name = model._meta.object_name
        opts = model._meta
        for operation in opts.default_permissions:
            group_basenames = [ActionGroupBasename.ADMIN]
            if operation == "add":
                action_action = "create"
            elif operation == "change":
                action_action = "update"
            else:
                action_action = operation
                if operation == "view":
                    group_basenames.append(ActionGroupBasename.VIEWER)
            action_id = f"{action_action}{object_name}"
            codename = get_permission_codename(operation, opts)
            self.register_action(
                action_id, namespace, group_basenames,
                LEGACY_PERM_APPLIES_TO,
                legacy_perm=f"{app_config.label}.{codename}",
            )

    def register_app_legacy_perms(self, app_config: AppConfig) -> None:
        permission_models = getattr(app_config, "permission_models", [])
        perm_registered = False
        for model in app_config.get_models():
            model_name = model._meta.model_name
            if (
                # Zentral model
                model_name not in permission_models
                # Auth Group
                and (app_config.label != "auth" or model._meta.model_name != "group")
            ):
                continue
            self._register_model_default_legacy_perm_actions(app_config, model)
            perm_registered = True
        if perm_registered:
            self._register_module_legacy_perm_action(app_config)

    def has_legacy_perm(self, user_obj, perm):
        # Uses a cache in the user object.
        # Group/Role membership changes within the lifetime of the user object may lead to inconsistent decisions.
        legacy_perm_cache_name = "_pbac_legacy_perms"
        sentinel = object()
        legacy_perm_cache = getattr(user_obj, legacy_perm_cache_name, sentinel)
        if legacy_perm_cache == sentinel:
            legacy_perm_cache = {}
            setattr(user_obj, legacy_perm_cache_name, legacy_perm_cache)
        try:
            return legacy_perm_cache[perm]
        except KeyError:
            action = self.legacy_perm_actions.get(perm)
            if action is None:
                legacy_perm_cache[perm] = False
                return False
            request = Request(
                Principal.from_user(user_obj),
                action,
                self.system_any_resource,
            )
            self.authorize_request(request)
            legacy_perm_cache[perm] = request.is_authorized
            return request.is_authorized

    def has_module_legacy_perms(self, user_obj, app_label):
        # Uses a cache in the user object.
        # Group/Role membership changes within the lifetime of the user object may lead to inconsistent decisions.
        module_legacy_perm_cache_name = "_pbac_module_legacy_perms"
        sentinel = object()
        module_legacy_perm_cache = getattr(user_obj, module_legacy_perm_cache_name, sentinel)
        if module_legacy_perm_cache == sentinel:
            module_legacy_perm_cache = {}
            setattr(user_obj, module_legacy_perm_cache_name, module_legacy_perm_cache)
        try:
            return module_legacy_perm_cache[app_label]
        except KeyError:
            action = self.module_legacy_perm_actions.get(app_label)
            if action is None:
                module_legacy_perm_cache[app_label] = False
                return False
            request = Request(
                Principal.from_user(user_obj),
                action,
                self.system_any_resource,
            )
            self.authorize_request(request)
            module_legacy_perm_cache[app_label] = request.is_authorized
            return request.is_authorized

    # Cedar schema (lazily built, cached). Bust with
    # ``del engine.cedar_schema_json`` if you've re-registered something
    # at runtime — production code never should.
    @cached_property
    def cedar_schema_json(self):
        return render_schema_json(build_schema_ir(self))

    def authorize_request(self, request: Request):
        if request.is_pending:
            authorize_request(request, self.cedar_schema_json)

    def authorize_requests(self, requests: list[Request]):
        authorize_requests(
            [r for r in requests if r.is_pending],
            self.cedar_schema_json,
        )


engine = Engine()
