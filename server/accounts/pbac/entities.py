from typing import Dict, Optional
from typing_extensions import Self


class Namespace:
    def __init__(self, id: str) -> None:
        self.id = id

    def __str__(self):
        return self.id

    def __repr__(self):
        return f"Namespace <{self.id}>"


class Entity:
    def __init__(
        self,
        type: str,
        id: str,
        namespace: Optional[Namespace] = None,
        parents: Optional[list[Self]] = None,
        attrs: Optional[dict] = None,
    ) -> None:
        self.type = type
        self.id = id
        self.namespace = namespace
        self.parents = parents or []
        self.attrs = attrs or {}

    @property
    def full_type(self):
        if self.namespace:
            return f"{self.namespace}::{self.type}"
        return self.type

    def __str__(self):
        return f'{self.full_type}::"{self.id}"'

    def __repr__(self):
        return f"{self.__class__.__name__} <{self}>"


class Resource(Entity):
    pass


class Principal(Entity):
    @classmethod
    def from_user(cls, user_obj) -> Self:
        entity_cache_name = "_pbac_principal"
        if not hasattr(user_obj, entity_cache_name):
            principal = cls(
                "ServiceAccount" if user_obj.is_service_account else "User",
                str(user_obj.pk),
                parents=[
                    Entity("Role", str(g.pk))
                    for g in user_obj.groups.all()
                ],
                attrs={"is_superuser": not user_obj.is_service_account and user_obj.is_superuser}
            )
            setattr(user_obj, entity_cache_name, principal)
        return getattr(user_obj, entity_cache_name)

    @property
    def is_superuser(self):
        return self.type == "User" and self.attrs.get("is_superuser") is True


ACTION_ENTITY_TYPE = "Action"


class ActionGroup(Entity):
    def __init__(self, id: str, namespace: Optional[Namespace] = None) -> None:
        return super().__init__(ACTION_ENTITY_TYPE, id, namespace)


class Action(Entity):
    def __init__(self, id: str, namespace: Optional[Namespace], parents: Optional[list[ActionGroup]] = None) -> None:
        return super().__init__(ACTION_ENTITY_TYPE, id, namespace, parents)


class Request:
    def __init__(
        self,
        principal: Principal,
        action: Action,
        resource: Resource,
        context: Optional[Dict] = None
    ) -> None:
        self.principal = principal
        self.action = action
        self.resource = resource
        self.context = context or {}
        if self.principal.is_superuser:
            self.is_authorized = True
        else:
            self.is_authorized = None

    @property
    def is_pending(self):
        return self.is_authorized is None

    @property
    def correlation_id(self):
        return str(id(self))

    def get_authorized_display(self):
        if self.is_pending:
            return "Pending"
        elif self.is_authorized is True:
            return "Authorized"
        else:
            return "Denied"

    def __repr__(self):
        return f"Request <{self.principal} {self.action} {self.resource}> {self.get_authorized_display()}"
