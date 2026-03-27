import logging
import re
from typing import Optional
from django.apps.config import AppConfig
from django.contrib.auth import get_permission_codename
from django.db.models.base import ModelBase
from .cedar import authorize_request, authorize_requests
from .entities import Action, ActionGroup, Namespace, Principal, Request, Resource


logger = logging.getLogger("zentral.accounts.pbac.engine")


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

    def get_action_group(self, id: str, namespace: Optional[Namespace] = None) -> ActionGroup:
        key = (id, namespace)
        if key not in self.action_groups:
            self.action_groups[key] = ActionGroup(id, namespace)
        return self.action_groups[key]

    def get_action(self, id: str, namespace: Namespace, parents: Optional[list[ActionGroup]] = None) -> Action:
        key = (id, namespace)
        if key not in self.actions:
            self.actions[key] = Action(id, namespace, parents)
        return self.actions[key]

    # legacy perms

    def _get_app_config_namespace(self, app_config: AppConfig) -> Namespace:
        app_name = app_config.name.split(".")[-1]
        id = "".join(
            w.upper() if w in ("mdm",) else w.title()
            for w in re.split(r"[ _]", app_name)
        )
        return self.get_namespace(id)

    def _register_module_legacy_perm_action(self, app_config: AppConfig) -> None:
        namespace = self._get_app_config_namespace(app_config)
        action_id = "NOOP"
        group_id = "ViewerActions"
        action_groups = [
            self.get_action_group(group_id, namespace),
            self.get_action_group(group_id)
        ]
        self.module_legacy_perm_actions[app_config.label] = self.get_action(action_id, namespace, action_groups)

    def _register_legacy_perm_action(
        self,
        app_config: AppConfig,
        codename: str,
        action_id: str,
        group_basenames: list[str]
    ) -> None:
        namespace = self._get_app_config_namespace(app_config)
        action_groups = []
        for group_basename in group_basenames:
            group_id = f"{group_basename}Actions"
            action_groups.append(self.get_action_group(group_id, namespace))
            action_groups.append(self.get_action_group(group_id))
        action = self.get_action(action_id, namespace, action_groups)
        self.legacy_perm_actions[f"{app_config.label}.{codename}"] = action

    def _register_model_default_legacy_perm_actions(self, app_config: AppConfig, model: ModelBase) -> None:
        object_name = model._meta.object_name
        opts = model._meta
        for operation in opts.default_permissions:
            codename = get_permission_codename(operation, opts)
            group_basenames = ["Admin"]
            if object_name == "MachineTag":
                group_basenames.append("User")
            if operation == "add":
                action_action = "create"
            elif operation == "change":
                action_action = "update"
            else:
                action_action = operation
                if operation == "view":
                    group_basenames.append("Viewer")
            action_id = f"{action_action}{object_name}"
            self._register_legacy_perm_action(app_config, codename, action_id, group_basenames)

    def _register_model_custom_legacy_perm_actions(self, app_config: AppConfig, model: ModelBase) -> None:
        for codename, _ in model._meta.permissions:
            action_id_items = []
            for i, w in enumerate(codename.split("_")):
                if w in ("prk",):
                    w = w.upper()
                elif w == "depdevice":
                    w = "DEPDevice"
                elif i > 0:
                    w = w.title()
                action_id_items.append(w)
            action_id = "".join(action_id_items)
            self._register_legacy_perm_action(app_config, codename, action_id, ["Admin", "User"])

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
            self._register_model_custom_legacy_perm_actions(app_config, model)
            perm_registered = True
        if perm_registered:
            self._register_module_legacy_perm_action(app_config)

    def has_legacy_perm(self, user_obj, perm):
        action = self.legacy_perm_actions.get(perm)
        if action is None:
            return False
        request = Request(
            Principal.from_user(user_obj),
            action,
            self.system_any_resource,
        )
        self.authorize_request(request)
        return request.is_authorized

    def has_module_legacy_perms(self, user_obj, app_label):
        action = self.module_legacy_perm_actions.get(app_label)
        if action is None:
            return False
        request = Request(
            Principal.from_user(user_obj),
            action,
            self.system_any_resource,
        )
        self.authorize_request(request)
        return request.is_authorized

    def authorize_request(self, request: Request):
        if request.is_pending:
            authorize_request(request)

    def authorize_requests(self, requests: list[Request]):
        authorize_requests([r for r in requests if r.is_pending])


engine = Engine()
