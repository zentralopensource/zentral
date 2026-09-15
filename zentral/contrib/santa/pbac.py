from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import (
    SERVICE_ACCOUNT,
    SYSTEM,
    USER,
    AppliesTo,
    AttrSpec,
    ResourceType,
)

from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.pbac import MACHINE_RESOURCE_TYPE, get_meta_machine_resource

from .models import EnrolledMachine, ScopedClientMode


# namespace


NAMESPACE_ID = "Santa"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions
#
# Neither action carries a legacy_perm: the enrolled machine model is out of the app
# config permission_models, so there is no Django permission to fall back on and the
# typed PBAC path is the only way in.


# viewEnrolledMachine applies to System rather than to a machine on purpose. The PBAC
# engine decides once per request, and scoping the list endpoint to a meta business unit
# would take a decision per row: filtering the page after it was cut would return short
# pages. Cedar can partially evaluate a request with an unknown resource and hand back the
# residual, which would compile into a queryset filter, but a policy to SQL compiler has to
# be exact in both directions - a permit residual it cannot compile hides machines, a
# forbid residual it cannot compile leaks them - so it is its own piece of work.
view_enrolled_machine_action = engine.register_action(
    "viewEnrolledMachine",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(SYSTEM,),
        context={},
    ),
    help_text="See the machines that are enrolled in Santa. The decision is not scoped to a machine.",
)


# forceCleanSync takes the inventory machine resource, so a policy can be scoped to a
# meta business unit. Every context attribute is required: no legacy request ever reaches
# this action with an empty context, so a policy can read them without a has guard.
force_clean_sync_action = engine.register_action(
    "forceCleanSync",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(MACHINE_RESOURCE_TYPE,),
        context={
            "syncType": AttrSpec(
                str,
                help_text="The type of clean sync. A cancellation carries the type of the sync "
                          "that it takes back.",
                # NORMAL never reaches the context: a queued normal sync would mean nothing,
                # so both entry points reject it before the decision is made
                values=sorted(EnrolledMachine.SyncType.clean_values()),
            ),
            "configurationName": AttrSpec(
                str,
                help_text="The name of the Santa configuration of the machine.",
            ),
            "configurationID": AttrSpec(
                int,
                help_text="The primary key of the Santa configuration of the machine.",
            ),
        },
    ),
    help_text="Queue a clean sync for the next Santa preflight of a machine. It also authorizes "
              "the cancellation of a queued clean sync.",
)


# requests


class ViewEnrolledMachineRequest(Request):
    def __init__(self, user_obj) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            view_enrolled_machine_action,
            engine.system_any_resource,
        )


class ForceCleanSyncRequest(Request):
    def __init__(self, user_obj, machine: MetaMachine, enrolled_machine, sync_type) -> None:
        configuration = enrolled_machine.enrollment.configuration
        super().__init__(
            Principal.from_user(user_obj),
            force_clean_sync_action,
            get_meta_machine_resource(machine),
            {"syncType": str(sync_type),
             "configurationName": configuration.name,
             "configurationID": configuration.pk},
        )


# scoped client mode


CONFIGURATION_RESOURCE_TYPE = ResourceType(
    "Configuration", get_namespace(),
    attrs={"name": AttrSpec(str, help_text="The name of the Santa configuration.")},
)


SCOPED_CLIENT_MODE_RESOURCE_TYPE = ResourceType(
    "ScopedClientMode", get_namespace(),
    parents=(CONFIGURATION_RESOURCE_TYPE,),
)


def get_configuration_resource(configuration) -> Resource:
    return Resource(
        CONFIGURATION_RESOURCE_TYPE.name, str(configuration.pk), CONFIGURATION_RESOURCE_TYPE.namespace,
        attrs={"name": configuration.name},
    )


def get_scoped_client_mode_resource(scoped_client_mode) -> Resource:
    return Resource(
        SCOPED_CLIENT_MODE_RESOURCE_TYPE.name, str(scoped_client_mode.pk),
        SCOPED_CLIENT_MODE_RESOURCE_TYPE.namespace,
        [get_configuration_resource(scoped_client_mode.configuration)],
    )


create_scoped_client_mode_action = engine.register_action(
    "createScopedClientMode",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(CONFIGURATION_RESOURCE_TYPE,),
        context={},
    ),
    help_text="Add a scoped client mode to a Santa configuration.",
)


view_scoped_client_mode_action = engine.register_action(
    "viewScopedClientMode",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(SCOPED_CLIENT_MODE_RESOURCE_TYPE,),
        context={},
    ),
    help_text="See the scoped client modes of a Santa configuration.",
)


update_scoped_client_mode_action = engine.register_action(
    "updateScopedClientMode",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(SCOPED_CLIENT_MODE_RESOURCE_TYPE,),
        context={},
    ),
    help_text="Change a scoped client mode.",
)


delete_scoped_client_mode_action = engine.register_action(
    "deleteScopedClientMode",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=AppliesTo(
        principals=(USER, SERVICE_ACCOUNT),
        resources=(SCOPED_CLIENT_MODE_RESOURCE_TYPE,),
        context={},
    ),
    help_text="Remove a scoped client mode from a Santa configuration.",
)


class CreateScopedClientModeRequest(Request):
    def __init__(self, user_obj, configuration) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            create_scoped_client_mode_action,
            get_configuration_resource(configuration),
        )


class BaseScopedClientModeRequest(Request):
    action = None

    def __init__(self, user_obj, scoped_client_mode: ScopedClientMode) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            self.action,
            get_scoped_client_mode_resource(scoped_client_mode),
        )


class ViewScopedClientModeRequest(BaseScopedClientModeRequest):
    action = view_scoped_client_mode_action


class UpdateScopedClientModeRequest(BaseScopedClientModeRequest):
    action = update_scoped_client_mode_action


class DeleteScopedClientModeRequest(BaseScopedClientModeRequest):
    action = delete_scoped_client_mode_action
