from pbac.engine import engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import ResourceType

from zentral.utils.pbac_secrets import register_view_secrets_action

from .models import Store


# namespace


NAMESPACE_ID = "Stores"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resource types


STORE_RESOURCE_TYPE = ResourceType("Store", get_namespace())


# actions


view_store_secrets_action = register_view_secrets_action(
    "viewStoreSecrets",
    STORE_RESOURCE_TYPE,
    "See the secrets of the backend of a store: passwords, tokens and keys. Without this action, the API "
    "returns their hashes.",
)


# resources


def get_store_resource(store: Store) -> Resource:
    return Resource("Store", str(store.pk), get_namespace())


# requests


class ViewStoreSecretsRequest(Request):
    def __init__(self, user_obj, store: Store) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            view_store_secrets_action,
            get_store_resource(store),
        )
