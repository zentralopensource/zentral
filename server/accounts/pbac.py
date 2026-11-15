from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import SERVICE_ACCOUNT, USER, AppliesTo, ResourceType
from pbac.utils import permitted_pks


# namespace


NAMESPACE_ID = "Accounts"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resources


# An issuer is a member of its service account: a policy gives the conditions of the issuers of one account with
# `resource in ServiceAccount::"…"`, or of the accounts of one role with `resource in Role::"…"`.
OIDC_API_TOKEN_ISSUER_RESOURCE_TYPE = ResourceType("OIDCAPITokenIssuer", get_namespace(), parents=(SERVICE_ACCOUNT,))


def with_oidc_api_token_issuer_resource_relations(queryset):
    # the service account of each issuer, and its roles, without a query for each row
    return queryset.select_related("user").prefetch_related("user__groups")


def get_oidc_api_token_issuer_resource(issuer) -> Resource:
    # The service account with its roles, as when it is the principal: the first entity of an id wins, so a
    # parent without its roles would make `resource in Role::"…"` depend on the caller.
    # Zentral gives an issuer to a service account only, but the database does not enforce it: an issuer of a
    # user, from a manual edit, belongs to no account.
    parents = [Principal.from_user(issuer.user)] if issuer.user.is_service_account else []
    return Resource(OIDC_API_TOKEN_ISSUER_RESOURCE_TYPE.name, str(issuer.pk), get_namespace(), parents)


# actions


# The CEL condition names the workloads that get an API token of the service account, so it shows an attacker
# which one to compromise. The other fields of an issuer stay with viewOIDCAPITokenIssuer.
view_oidc_api_token_issuer_condition_action = engine.register_action(
    "viewOIDCAPITokenIssuerCondition",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(OIDC_API_TOKEN_ISSUER_RESOURCE_TYPE,),
        context={},
    ),
    help_text="See the CEL condition of an OIDC API token issuer: the workloads that get an API token of its "
              "service account.",
)


# requests


class ViewOIDCAPITokenIssuerConditionRequest(Request):
    def __init__(self, user_obj, issuer) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            view_oidc_api_token_issuer_condition_action,
            get_oidc_api_token_issuer_resource(issuer),
        )


def issuers_with_visible_condition(http_request, issuers):
    """The primary keys of the issuers whose CEL condition the user of the request can see, in one Cedar call.

    A condition that is left out of a response is a filter, not a refused decision: no log (rule 14). Without a
    request, no condition is visible.
    """
    if http_request is None:
        return set()
    return permitted_pks(http_request.user, ViewOIDCAPITokenIssuerConditionRequest, issuers)
