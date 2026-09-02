import logging

from django.core.exceptions import PermissionDenied
from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request
from pbac.types import SERVICE_ACCOUNT, SYSTEM, USER, AppliesTo, AttrSpec

from zentral.contrib.inventory.pbac import MACHINE_RESOURCE_TYPE, get_meta_machine_resource


logger = logging.getLogger("zentral.contrib.turbo.pbac")


# namespace


NAMESPACE_ID = "Turbo"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions
#
# The plain CRUD of a Command stays on the legacy-perm path: it is a global definition object with its
# own list page and no container, so there is nothing to scope by. `createCommand` in particular must
# NOT carry the backend in its context — the console's create button reaches it through the legacy path
# with an empty context, a policy reading context.backend would error there, an erroring policy is
# skipped, and the button would vanish for exactly the users the policy grants.
#
# Scheduling is different: it names a machine and a kind, both known when the decision is made. That is
# what lets a policy say "may collect a sysdiagnose here, may not run a file_export anywhere" — which one
# turbo.add_onetimejob cannot express, since it covers both identically.

_SCHEDULE_COMMAND_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    # Machine on the machine page, System on the configuration page. The configuration-page flow has no
    # machine to name — only a scope expression (tags and serial arrays, whose membership changes after
    # the schedule is written) — so a policy keyed on the machine or its MBU holds on one path and does
    # not apply on the other. This action is therefore an ADDITIONAL gate rather than a replacement for
    # turbo.add_onetimejob: replacing the perm would make the configuration path look covered.
    resources=(MACHINE_RESOURCE_TYPE, SYSTEM),
    context={
        "backend": AttrSpec(str, required=False),
        "mode": AttrSpec(str, required=False),
    },
)


schedule_command_action = engine.register_action(
    "scheduleCommand",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_SCHEDULE_COMMAND_APPLIES_TO,
)


# requests


class ScheduleCommandRequest(Request):
    def __init__(self, user_obj, command, mode, machine=None) -> None:
        resource = get_meta_machine_resource(machine) if machine is not None else engine.system_any_resource
        super().__init__(
            Principal.from_user(user_obj),
            schedule_command_action,
            resource,
            # mode is "one_time" on every request today, since allowed_modes keeps a command off a
            # recurring schedule. It is here because it is free and known, and because it is what would
            # let "no recurring collection" be policy rather than code if that ever relaxes.
            {"backend": command.backend, "mode": str(mode)},
        )


def check_schedule_command(request, job, mode, machine=None):
    # no-op for a Script or an MSCPCheck: only a command kind carries a backend worth policing, and
    # gating the others here would change authorization for every shipped deployment
    if not job.is_command:
        return
    pbac_request = ScheduleCommandRequest(request.user, job.command, mode, machine)
    engine.authorize_request(pbac_request)
    if not pbac_request.is_authorized:
        logger.error("Permission denied %s", pbac_request, extra={"request": request})
        raise PermissionDenied
