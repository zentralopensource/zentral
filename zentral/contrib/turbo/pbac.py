import logging

from django.core.exceptions import PermissionDenied
from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import SERVICE_ACCOUNT, USER, AppliesTo, AttrSpec, ResourceType

from .models import Job


logger = logging.getLogger("zentral.contrib.turbo.pbac")


# namespace


NAMESPACE_ID = "Turbo"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resources
#
# createOneTimeJob takes the CONFIGURATION: the row it creates does not exist yet, so the resource is
# the container it will live in — which is also the one resource every entry point to that flow has.
# updateOneTimeJob and deleteOneTimeJob take the ROW, because by then it exists. The row is a member of
# its configuration, so a policy scoped to `Turbo::Configuration::"…"` covers all three actions, and it
# carries the job it runs, so a policy can read `resource.job` on the two that have a row.
#
# The machines are not a resource on any of them: a schedule targets tags and serial numbers whose
# membership changes after it is written, so no path has a machine to name.


CONFIGURATION_RESOURCE_TYPE = ResourceType("Configuration", get_namespace())
JOB_RESOURCE_TYPE = ResourceType("Job", get_namespace(), attrs={
    "kind": AttrSpec(str, help_text="The kind of the job.", values=Job.Kind.values),
})
ONE_TIME_JOB_RESOURCE_TYPE = ResourceType(
    "OneTimeJob", get_namespace(),
    attrs={"job": AttrSpec(JOB_RESOURCE_TYPE, help_text="The job the schedule runs.")},
    parents=(CONFIGURATION_RESOURCE_TYPE,),
)


def get_configuration_resource(configuration) -> Resource:
    return Resource("Configuration", str(configuration.pk), get_namespace())


def get_job_resource(job) -> Resource:
    return Resource("Job", str(job.pk), get_namespace(), attrs={"kind": job.kind})


def get_one_time_job_resource(one_time_job) -> Resource:
    return Resource("OneTimeJob", str(one_time_job.pk), get_namespace(),
                    [get_configuration_resource(one_time_job.configuration)],
                    attrs={"job": get_job_resource(one_time_job.job)})


# actions
#
# Only viewOneTimeJob stays on the legacy permission path. A typed view action would have to scope a
# LIST, which means filtering a queryset by policy rather than deciding one request — its own piece of
# work, and not this one. add / change / delete are opted out of the auto-registration in the model and
# registered here instead, so nothing can ask them through has_perm with System::"any".
#
# The context carries the JOB as an entity, on all three, so one policy can name all three:
#
#   forbid (
#     principal,
#     action in [Turbo::Action::"createOneTimeJob",
#                Turbo::Action::"updateOneTimeJob",
#                Turbo::Action::"deleteOneTimeJob"],
#     resource
#   ) when { context.job.kind == "file_export" };
#
# An entity rather than a kind string because it composes: `context.job.kind` says what a `job_kind`
# key would have said, and anything else the job comes to declare is readable without changing the
# shape of every action that carries it.


_JOB_CONTEXT = {
    # REQUIRED, and a policy reading it needs no guard. The console asks createOneTimeJob before a job
    # is picked too — to decide whether to offer it at all — but that question is a preview: its
    # context is unknown rather than empty, so partial evaluation residualizes the whole expression
    # instead of failing on a record that does not have it.
    "job": AttrSpec(JOB_RESOURCE_TYPE, help_text="The job being scheduled, or the job the schedule "
                                                 "being changed or removed runs."),
}


_CREATE_ONE_TIME_JOB_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(CONFIGURATION_RESOURCE_TYPE,),
    context=_JOB_CONTEXT,
)


_ROW_ONE_TIME_JOB_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(ONE_TIME_JOB_RESOURCE_TYPE,),
    context=_JOB_CONTEXT,
)


create_one_time_job_action = engine.register_action(
    "createOneTimeJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_CREATE_ONE_TIME_JOB_APPLIES_TO,
    help_text="Schedule a job to run once on the machines of a configuration. The resource is the "
              "configuration the schedule is created in, because the schedule does not exist yet, and "
              "`context.job` is the job being scheduled — so a policy can allow a sysdiagnose and "
              "refuse a file_export, or grant one configuration and not another.",
)


update_one_time_job_action = engine.register_action(
    "updateOneTimeJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_ROW_ONE_TIME_JOB_APPLIES_TO,
    help_text="Change a one-time job. The resource is the schedule itself, which is a member of its "
              "configuration and carries the job it runs, so `resource.job` and `context.job` are the "
              "same job. The job of a schedule cannot be changed; what an update can change is where "
              "and when it delivers — its tags, its serial numbers and its window. Widening the reach "
              "of a file_export schedule is a scheduling act.",
)


delete_one_time_job_action = engine.register_action(
    "deleteOneTimeJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_ROW_ONE_TIME_JOB_APPLIES_TO,
    help_text="Remove a one-time job. The resource is the schedule, as it is for a change. Removing a "
              "schedule stops it being served to the machines that have not run it yet, so a policy "
              "that governs a kind governs its removal too.",
)


# requests


class CreateOneTimeJobRequest(Request):
    def __init__(self, user_obj, configuration, job=None) -> None:
        # No job means the caller is asking whether to offer the action at all, before the user has
        # picked one. That is a preview: the context is unknown, not empty, and the engine answers it
        # by partial evaluation — Deny is definitive, anything else means "offer it and decide for
        # real on submit".
        super().__init__(
            Principal.from_user(user_obj),
            create_one_time_job_action,
            get_configuration_resource(configuration),
            {"job": get_job_resource(job)} if job is not None else None,
            unknown_context=job is None,
        )


class BaseOneTimeJobRowRequest(Request):
    # the row exists, so there is nothing to preview: every caller has the schedule and therefore its
    # job. No unknown context on these.
    pbac_action = None

    def __init__(self, user_obj, one_time_job) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            self.pbac_action,
            get_one_time_job_resource(one_time_job),
            {"job": get_job_resource(one_time_job.job)},
        )


class UpdateOneTimeJobRequest(BaseOneTimeJobRowRequest):
    pbac_action = update_one_time_job_action


class DeleteOneTimeJobRequest(BaseOneTimeJobRowRequest):
    pbac_action = delete_one_time_job_action


# checks


def _check(request, pbac_request):
    engine.authorize_request(pbac_request)
    if not pbac_request.is_authorized:
        logger.error("Permission denied %s", pbac_request, extra={"request": request})
        raise PermissionDenied


def check_create_one_time_job(request, configuration, job=None):
    _check(request, CreateOneTimeJobRequest(request.user, configuration, job))


def check_update_one_time_job(request, one_time_job):
    _check(request, UpdateOneTimeJobRequest(request.user, one_time_job))


def check_delete_one_time_job(request, one_time_job):
    _check(request, DeleteOneTimeJobRequest(request.user, one_time_job))


def can_create_one_time_job(user_obj, configuration):
    # the console button: a preview, since no job has been picked
    pbac_request = CreateOneTimeJobRequest(user_obj, configuration)
    engine.authorize_request(pbac_request)
    return pbac_request.is_authorized


def offerable_jobs(user_obj, configuration, queryset):
    """The jobs this principal may schedule in this configuration, for a form to OFFER.

    Only for the choices a picker renders — never for validating what comes back. Narrowing the
    field's queryset would move the gate from authorization to form validation: a refused kind would
    come back as "select a valid choice" instead of reaching the typed check, so nothing would be
    logged as a permission denial and the decision would no longer be made where it is made for the
    API. The caller assigns this to `field.choices` and leaves `field.queryset` whole.

    One batched evaluation for the page. Without it, the first thing an operator with a kind-scoped
    grant meets is a 403 page with the form lost.
    """
    jobs = list(queryset)
    if not jobs:
        return []
    requests = [CreateOneTimeJobRequest(user_obj, configuration, job) for job in jobs]
    engine.authorize_requests(requests)
    return [job for job, pbac_request in zip(jobs, requests) if pbac_request.is_authorized]


def authorize_one_time_job_rows(user_obj, one_time_jobs):
    """Annotate each one-time job with can_update and can_delete, in one batched decision.

    The console gates a button per row and the rows differ by job, so a single answer for the page
    would be wrong. authorize_requests batches them into one evaluation.
    """
    one_time_jobs = list(one_time_jobs)
    requests = []
    for one_time_job in one_time_jobs:
        requests.append(UpdateOneTimeJobRequest(user_obj, one_time_job))
        requests.append(DeleteOneTimeJobRequest(user_obj, one_time_job))
    engine.authorize_requests(requests)
    for index, one_time_job in enumerate(one_time_jobs):
        one_time_job.can_update = requests[2 * index].is_authorized
        one_time_job.can_delete = requests[2 * index + 1].is_authorized
    return one_time_jobs
