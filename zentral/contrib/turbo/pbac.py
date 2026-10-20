from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import SERVICE_ACCOUNT, USER, AppliesTo, AttrSpec, ResourceType
from pbac.utils import check_request

from .models import Job


# namespace


NAMESPACE_ID = "Turbo"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# resources
#
# A create action takes the CONFIGURATION, because the schedule does not exist yet. Every entry
# point to that flow has the configuration. An update or a delete action takes the SCHEDULE, which
# exists by then. A schedule is a member of its configuration, so one policy on
# `Turbo::Configuration::"…"` covers the six actions. A schedule also carries the job it runs, so a
# policy can read `resource.job` on an update or a delete.
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
RECURRING_JOB_RESOURCE_TYPE = ResourceType(
    "RecurringJob", get_namespace(),
    attrs={"job": AttrSpec(JOB_RESOURCE_TYPE, help_text="The job the schedule runs.")},
    parents=(CONFIGURATION_RESOURCE_TYPE,),
)


def get_configuration_resource(configuration) -> Resource:
    return Resource("Configuration", str(configuration.pk), get_namespace())


def get_job_resource(job) -> Resource:
    return Resource("Job", str(job.pk), get_namespace(), attrs={"kind": job.kind})


def _get_schedule_resource(resource_type, schedule) -> Resource:
    return Resource(resource_type.name, str(schedule.pk), get_namespace(),
                    [get_configuration_resource(schedule.configuration)],
                    attrs={"job": get_job_resource(schedule.job)})


# actions
#
# Only viewOneTimeJob and viewRecurringJob stay on the legacy permission path. A typed view action
# must scope a LIST, which means a policy filters a queryset instead of a decision on one request.
# That is separate work. JobScope excludes add, change and delete from the auto-registration, and
# this module registers them, so nothing can ask them through has_perm with System::"any".
#
# The context carries the JOB as an entity, on all six, so one policy can name them all:
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
    # REQUIRED, and a policy that reads it needs no guard. The console also asks a create action
    # before the operator picks a job, to decide if it offers the action. That question is a
    # preview: its context is unknown, not empty. Partial evaluation residualizes the expression
    # instead of a failure on a record without the attribute.
    "job": AttrSpec(JOB_RESOURCE_TYPE, help_text="The job being scheduled, or the job the schedule "
                                                 "being changed or removed runs."),
}


_CREATE_SCHEDULE_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(CONFIGURATION_RESOURCE_TYPE,),
    context=_JOB_CONTEXT,
)


_ROW_ONE_TIME_JOB_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(ONE_TIME_JOB_RESOURCE_TYPE,),
    context=_JOB_CONTEXT,
)


_ROW_RECURRING_JOB_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(RECURRING_JOB_RESOURCE_TYPE,),
    context=_JOB_CONTEXT,
)


create_one_time_job_action = engine.register_action(
    "createOneTimeJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_CREATE_SCHEDULE_APPLIES_TO,
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


create_recurring_job_action = engine.register_action(
    "createRecurringJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_CREATE_SCHEDULE_APPLIES_TO,
    help_text="Schedule a job to run repeatedly on the machines of a configuration. The resource is "
              "the configuration the schedule is created in, because the schedule does not exist yet, "
              "and `context.job` is the job being scheduled.",
)


update_recurring_job_action = engine.register_action(
    "updateRecurringJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_ROW_RECURRING_JOB_APPLIES_TO,
    help_text="Change a recurring job. The resource is the schedule, which is a member of its "
              "configuration and carries the job it runs. The job of a schedule cannot be changed. An "
              "update changes its tags, its serial numbers and its interval.",
)


delete_recurring_job_action = engine.register_action(
    "deleteRecurringJob",
    get_namespace(),
    [ActionGroupBasename.ADMIN],
    applies_to=_ROW_RECURRING_JOB_APPLIES_TO,
    help_text="Remove a recurring job. The resource is the schedule, as it is for a change.",
)


# requests


class BaseCreateScheduleRequest(Request):
    pbac_action = None

    def __init__(self, user_obj, configuration, job=None) -> None:
        # No job: the caller asks if it offers the action, before the operator picks a job. That
        # is a preview. The context is unknown, not empty, and the engine answers it by partial
        # evaluation. Deny is definitive. Any other answer means "offer the action, and decide
        # again on the submit".
        super().__init__(
            Principal.from_user(user_obj),
            self.pbac_action,
            get_configuration_resource(configuration),
            {"job": get_job_resource(job)} if job is not None else None,
            unknown_context=job is None,
        )


class CreateOneTimeJobRequest(BaseCreateScheduleRequest):
    pbac_action = create_one_time_job_action


class CreateRecurringJobRequest(BaseCreateScheduleRequest):
    pbac_action = create_recurring_job_action


class BaseScheduleRequest(Request):
    # The schedule exists, so there is no preview. Every caller has the schedule, and thus the
    # job. These requests always have a context.
    pbac_action = None
    resource_type = None

    def __init__(self, user_obj, schedule) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            self.pbac_action,
            _get_schedule_resource(self.resource_type, schedule),
            {"job": get_job_resource(schedule.job)},
        )


class UpdateOneTimeJobRequest(BaseScheduleRequest):
    pbac_action = update_one_time_job_action
    resource_type = ONE_TIME_JOB_RESOURCE_TYPE


class DeleteOneTimeJobRequest(BaseScheduleRequest):
    pbac_action = delete_one_time_job_action
    resource_type = ONE_TIME_JOB_RESOURCE_TYPE


class UpdateRecurringJobRequest(BaseScheduleRequest):
    pbac_action = update_recurring_job_action
    resource_type = RECURRING_JOB_RESOURCE_TYPE


class DeleteRecurringJobRequest(BaseScheduleRequest):
    pbac_action = delete_recurring_job_action
    resource_type = RECURRING_JOB_RESOURCE_TYPE


# checks


def check_create_one_time_job(request, configuration, job=None):
    check_request(request, CreateOneTimeJobRequest(request.user, configuration, job))


def _can_create(user_obj, create_request_class, configuration):
    # the console button: a preview, because the operator has not picked a job
    pbac_request = create_request_class(user_obj, configuration)
    engine.authorize_request(pbac_request)
    return pbac_request.is_authorized


def can_create_one_time_job(user_obj, configuration):
    return _can_create(user_obj, CreateOneTimeJobRequest, configuration)


def can_create_recurring_job(user_obj, configuration):
    return _can_create(user_obj, CreateRecurringJobRequest, configuration)


def offerable_jobs(user_obj, create_request_class, configuration, queryset):
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
    requests = [create_request_class(user_obj, configuration, job) for job in jobs]
    engine.authorize_requests(requests)
    return [job for job, pbac_request in zip(jobs, requests) if pbac_request.is_authorized]


def _authorize_schedule_rows(user_obj, update_request_class, delete_request_class, schedules):
    """Annotate each schedule with can_update and can_delete, in one batched decision.

    The console gates a button per row and the rows differ by job, so a single answer for the page
    would be wrong. authorize_requests batches them into one evaluation.
    """
    schedules = list(schedules)
    requests = []
    for schedule in schedules:
        requests.append(update_request_class(user_obj, schedule))
        requests.append(delete_request_class(user_obj, schedule))
    engine.authorize_requests(requests)
    for index, schedule in enumerate(schedules):
        schedule.can_update = requests[2 * index].is_authorized
        schedule.can_delete = requests[2 * index + 1].is_authorized
    return schedules


def authorize_one_time_job_rows(user_obj, one_time_jobs):
    return _authorize_schedule_rows(user_obj, UpdateOneTimeJobRequest, DeleteOneTimeJobRequest, one_time_jobs)


def authorize_recurring_job_rows(user_obj, recurring_jobs):
    return _authorize_schedule_rows(user_obj, UpdateRecurringJobRequest, DeleteRecurringJobRequest,
                                    recurring_jobs)
