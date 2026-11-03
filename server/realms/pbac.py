from pbac.engine import engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import SERVICE_ACCOUNT, AppliesTo, ResourceType

from .models import Realm

# namespace


NAMESPACE_ID = "Realms"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resource types


REALM_RESOURCE_TYPE = ResourceType("Realm", get_namespace())


# actions
#
# provisionRealm is the only decision of the SCIM endpoints. It is in no action group: a policy that
# gives the admin actions does not give the IdP the realm groups, and their roles. Service accounts
# only: the IdP keeps its token, and a user keeps the checks of the console. The engine passes no
# schema at decision time, so the SCIM views refuse a user before they ask it.


provision_realm_action = engine.register_action(
    "provisionRealm",
    get_namespace(),
    [],
    applies_to=AppliesTo(
        principals=(SERVICE_ACCOUNT,),
        resources=(REALM_RESOURCE_TYPE,),
        context={},
    ),
    help_text=("Write the users, the groups and the group members of a realm through SCIM. "
               "Service accounts only."),
)


# resources


def get_realm_resource(realm: Realm) -> Resource:
    return Resource("Realm", str(realm.pk), get_namespace())


# requests


class ProvisionRealmRequest(Request):
    def __init__(self, user_obj, realm: Realm) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            provision_realm_action,
            get_realm_resource(realm),
        )


def is_scim_account(service_account) -> bool:
    """True if a policy gives the account provisionRealm, on all the realms or on some of them."""
    # asked as an active account: a token made while it is inactive works when it is active again
    principal = Principal(
        "ServiceAccount", str(service_account.pk),
        is_active=True,
        parents=Principal.from_user(service_account).parents,
    )
    return engine.undecided_policies(Request(principal, provision_realm_action, None)) is not False
