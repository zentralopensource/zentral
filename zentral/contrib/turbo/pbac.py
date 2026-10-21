import logging

from pbac.engine import ActionGroupBasename, engine
from pbac.entities import Namespace, Principal, Request, Resource
from pbac.types import SERVICE_ACCOUNT, USER, AppliesTo, AttrSpec, ResourceType
from pbac.utils import check_request

from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.inventory.pbac import MACHINE_RESOURCE_TYPE, get_meta_machine_resource

from .models import Job, OneTimeJob, resolve_upload_schedules


logger = logging.getLogger("zentral.contrib.turbo.pbac")


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


# A collected artifact has two containers. The machine tells whose data it is, and gives the meta business
# unit scope with the parents of Inventory::Machine. The schedule tells which job collected it, and it is a
# member of its configuration, so that one policy covers the scheduling and the artifacts:
#
#   forbid (
#     principal,
#     action in [Turbo::Action::"createOneTimeJob", Turbo::Action::"updateOneTimeJob",
#                Turbo::Action::"deleteOneTimeJob", Turbo::Action::"viewJobUpload",
#                Turbo::Action::"downloadJobUpload"],
#     resource in Turbo::Configuration::"…"
#   );
#
# The two containers can disagree: a configuration of one team can collect from a machine in the meta
# business unit of another team. A forbid on one of them applies.


JOB_UPLOAD_RESOURCE_TYPE = ResourceType(
    "JobUpload", get_namespace(),
    attrs={
        "artifact": AttrSpec(str, help_text="The declared output of the job kind, for example the "
                                            "archive of a sysdiagnose or the manifest of a file export."),
        "job": AttrSpec(JOB_RESOURCE_TYPE, help_text="The job of the run that collected the artifact."),
    },
    parents=(MACHINE_RESOURCE_TYPE, ONE_TIME_JOB_RESOURCE_TYPE, RECURRING_JOB_RESOURCE_TYPE),
)


def get_configuration_resource(configuration) -> Resource:
    return Resource("Configuration", str(configuration.pk), get_namespace())


def get_job_resource(job) -> Resource:
    return Resource("Job", str(job.pk), get_namespace(), attrs={"kind": job.kind})


def _get_schedule_resource(resource_type, schedule) -> Resource:
    return Resource(resource_type.name, str(schedule.pk), get_namespace(),
                    [get_configuration_resource(schedule.configuration)],
                    attrs={"job": get_job_resource(schedule.job)})


def get_schedule_resource(schedule) -> Resource:
    resource_type = ONE_TIME_JOB_RESOURCE_TYPE if isinstance(schedule, OneTimeJob) else RECURRING_JOB_RESOURCE_TYPE
    return _get_schedule_resource(resource_type, schedule)


def get_job_upload_resource(upload, machine, schedule) -> Resource:
    # the caller gives the machine: get_meta_machine_resource keeps its parents on the object, so one
    # MetaMachine for each serial number makes one query, not one query for each row
    return Resource(
        "JobUpload", str(upload.pk), get_namespace(),
        [get_meta_machine_resource(machine), get_schedule_resource(schedule)],
        attrs={"artifact": upload.artifact, "job": get_job_resource(schedule.job)},
    )


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


# The two artifact actions have the same applies_to, but not the same groups. To see that a sysdiagnose
# exists is a view. A download gives the data of the person who uses the machine, so the Viewer group
# does not have downloadJobUpload, also without a policy.
#
# No context: the upload has all the data of the decision, so there is no preview.


_JOB_UPLOAD_APPLIES_TO = AppliesTo(
    principals=(USER, SERVICE_ACCOUNT),
    resources=(JOB_UPLOAD_RESOURCE_TYPE,),
)


view_job_upload_action = engine.register_action(
    "viewJobUpload",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER],
    applies_to=_JOB_UPLOAD_APPLIES_TO,
    help_text="See that a job collected an artifact from a machine, and the state of the upload. The "
              "resource is the upload. It is a member of the machine and of the schedule, and the "
              "schedule is a member of its configuration, so a policy can use all of them. It has the "
              "artifact name, and the job as an entity, so a policy can read `resource.job.kind`.",
)


download_job_upload_action = engine.register_action(
    "downloadJobUpload",
    get_namespace(),
    [ActionGroupBasename.ADMIN, ActionGroupBasename.USER],
    applies_to=_JOB_UPLOAD_APPLIES_TO,
    help_text="Download the artifact that a job collected from a machine. The resource is the same as "
              "for viewJobUpload. A sysdiagnose has the data of the person who uses the machine, so the "
              "Viewer group does not have this action.",
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


class BaseJobUploadRequest(Request):
    # the caller has the upload, so there is no preview
    pbac_action = None

    def __init__(self, user_obj, upload, machine, schedule) -> None:
        super().__init__(
            Principal.from_user(user_obj),
            self.pbac_action,
            get_job_upload_resource(upload, machine, schedule),
        )


class ViewJobUploadRequest(BaseJobUploadRequest):
    pbac_action = view_job_upload_action


class DownloadJobUploadRequest(BaseJobUploadRequest):
    pbac_action = download_job_upload_action


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


def check_download_job_upload(request, upload, schedule):
    check_request(request, DownloadJobUploadRequest(request.user, upload, MetaMachine(upload.serial_number), schedule))


def authorize_job_upload_rows(user_obj, uploads):
    """The uploads that the user can see, each with can_download, in one batched decision.

    The rows have different machines, configurations and jobs, so one answer for the page is not
    correct. An upload that the user cannot see is not on the page, so its name and its size stay
    hidden. An upload without its schedule is not on the page either: there is no configuration and no
    job for the decision.
    """
    uploads = list(uploads)
    schedules = resolve_upload_schedules(uploads)
    machines = {}
    placed = []
    requests = []
    for upload in uploads:
        schedule = schedules.get(upload.schedule_pk)
        if schedule is None:
            logger.warning("Turbo upload %s: no schedule %s", upload.pk, upload.schedule_pk)
            continue
        machine = machines.setdefault(upload.serial_number, MetaMachine(upload.serial_number))
        upload.job = schedule.job
        placed.append(upload)
        requests.append(ViewJobUploadRequest(user_obj, upload, machine, schedule))
        requests.append(DownloadJobUploadRequest(user_obj, upload, machine, schedule))
    engine.authorize_requests(requests)
    visible = []
    for index, upload in enumerate(placed):
        if not requests[2 * index].is_authorized:
            continue
        upload.can_download = requests[2 * index + 1].is_authorized
        visible.append(upload)
    return visible


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
