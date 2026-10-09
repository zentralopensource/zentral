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
# createOneTimeJob takes the CONFIGURATION, because the row does not exist yet. Every entry point
# to that flow has the configuration. updateOneTimeJob and deleteOneTimeJob take the ROW, which
# exists by then. The row is a member of its configuration, so one policy on
# `Turbo::Configuration::"…"` covers all three actions. The row also carries the job it runs, so a
# policy can read `resource.job` on the last two.
#
# A machine is not a resource on any of them. A schedule targets tags and serial numbers, and the
# members change after an operator writes it. No path has a machine to name.


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
# Only viewOneTimeJob stays on the legacy permission path. A typed view action must scope a LIST,
# which means a policy filters a queryset instead of a decision on one request. That is separate
# work. The model excludes add, change and delete from the auto-registration, and this module
# registers them, so nothing can ask them through has_perm with System::"any".
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
# The context carries an entity, not a kind string. `context.job.kind` gives what a `job_kind` key
# gives. A policy can also read any other attribute that the job declares later, and the actions
# keep their shape.


_JOB_CONTEXT = {
    # REQUIRED, and a policy that reads it needs no guard. The console also asks createOneTimeJob
    # before the operator picks a job, to decide if it offers the action. That question is a
    # preview: its context is unknown, not empty. Partial evaluation residualizes the expression
    # instead of a failure on a record without the attribute.
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
        # No job: the caller asks if it offers the action, before the operator picks a job. That
        # is a preview. The context is unknown, not empty, and the engine answers it by partial
        # evaluation. Deny is definitive. Any other answer means "offer the action, and decide
        # again on the submit".
        super().__init__(
            Principal.from_user(user_obj),
            create_one_time_job_action,
            get_configuration_resource(configuration),
            {"job": get_job_resource(job)} if job is not None else None,
            unknown_context=job is None,
        )


class BaseOneTimeJobRowRequest(Request):
    # The row exists, so there is no preview. Every caller has the schedule, and thus the job.
    # These requests always have a context.
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
    # the console button: a preview, because the operator has not picked a job
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
