from enum import Enum
import logging
from typing import Optional

from django.apps.config import AppConfig
from django.contrib.auth import get_permission_codename
from django.db.models.base import ModelBase

from .cedar import authorize_request, authorize_requests
from .entities import Action, ActionGroup, Namespace, Principal, Request, Resource


logger = logging.getLogger("zentral.pbac.engine")


class ActionGroupBasename(Enum):
    ADMIN = "Admin"
    USER = "User"
    VIEWER = "Viewer"

    def __str__(self):
        return self.value


class Engine:
    def __init__(self) -> None:
        self.namespaces = {}
        self.action_groups = {}
        self.actions = {}
        self.module_legacy_perm_actions = {}
        self.legacy_perm_actions = {}
        self.system_any_resource = Resource("System", "any")

    def get_namespace(self, id: str) -> Namespace:
        if id not in self.namespaces:
            self.namespaces[id] = Namespace(id)
        return self.namespaces[id]

    def get_action_group(self, basename: ActionGroupBasename, namespace: Optional[Namespace] = None) -> ActionGroup:
        id = f"{basename}Actions"
        key = (id, namespace)
        if key not in self.action_groups:
            self.action_groups[key] = ActionGroup(id, namespace)
        return self.action_groups[key]

    def get_action(
        self,
        id: str,
        namespace: Namespace,
        group_basenames: Optional[list[ActionGroupBasename]] = None,
        legacy_perm: Optional[str] = None,
    ) -> Action:
        key = (id, namespace)
        action_groups = []
        if group_basenames:
            for group_basename in group_basenames:
                # add namespace scoped action group
                action_groups.append(self.get_action_group(group_basename, namespace))
                # add global action group
                action_groups.append(self.get_action_group(group_basename))
        action = self.actions.get(key)
        if not action:
            self.actions[key] = action = Action(id, namespace, action_groups)
        if legacy_perm and legacy_perm not in self.legacy_perm_actions:
            self.legacy_perm_actions[legacy_perm] = action
        assert action_groups == action.parents
        return action

    # legacy perms

    def _get_app_config_namespace(self, app_config: AppConfig) -> Namespace:
        namespace_id = getattr(app_config, "pbac_namespace_id", app_config.name.split(".")[-1].title())
        return self.get_namespace(namespace_id)

    def _register_module_legacy_perm_action(self, app_config: AppConfig) -> None:
        namespace = self._get_app_config_namespace(app_config)
        action_id = "NOOP"
        self.module_legacy_perm_actions[app_config.label] = self.get_action(
            action_id, namespace,
            [ActionGroupBasename.VIEWER],
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
            self.get_action(action_id, namespace, group_basenames, f"{app_config.label}.{codename}")

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

    def authorize_request(self, request: Request):
        if request.is_pending:
            authorize_request(request)

    def authorize_requests(self, requests: list[Request]):
        authorize_requests([r for r in requests if r.is_pending])


engine = Engine()
