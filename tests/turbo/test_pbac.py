from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from pbac.types import LEGACY_PERM_APPLIES_TO
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import Job
from zentral.contrib.turbo.pbac import (JOB_RESOURCE_TYPE, CreateOneTimeJobRequest,
                                        DeleteOneTimeJobRequest,
                                        UpdateOneTimeJobRequest, authorize_one_time_job_rows,
                                        can_create_one_time_job, check_create_one_time_job,
                                        check_delete_one_time_job, check_update_one_time_job,
                                        create_one_time_job_action, delete_one_time_job_action,
                                        get_configuration_resource, get_one_time_job_resource,
                                        update_one_time_job_action)

from .utils import (forbid_job_kind_policy, force_command, force_configuration, force_one_time_job,
                    force_script, turbo_policy)


class TurboPBACTestCase(TestCase):
    maxDiff = None
    ACTIONS = (create_one_time_job_action, update_one_time_job_action, delete_one_time_job_action)

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    def _grant(self, condition=None):
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": turbo_policy(self.group, condition=condition)})

    def _forbid_kind(self, kind):
        Policy.objects.update_or_create(name="Turbo forbid",
                                        defaults={"source": forbid_job_kind_policy(kind)})

    def _authorized(self, pbac_request):
        engine.authorize_request(pbac_request)
        return pbac_request.is_authorized

    class _FakeRequest:
        def __init__(self, user):
            self.user = user

    # the resource

    def test_the_resource_is_the_configuration(self):
        configuration = force_configuration()
        self.assertEqual(str(get_configuration_resource(configuration)),
                         f'Turbo::Configuration::"{configuration.pk}"')

    def test_create_takes_the_configuration_and_the_others_take_the_row(self):
        # The row does not exist at the create, so create takes the container. The row exists
        # at an update or a delete, and is the resource.
        self.assertEqual([r.name for r in create_one_time_job_action.applies_to.resources],
                         ["Configuration"])
        for action in (update_one_time_job_action, delete_one_time_job_action):
            self.assertEqual([r.name for r in action.applies_to.resources], ["OneTimeJob"])

    def test_the_row_is_a_member_of_its_configuration(self):
        # one policy on a configuration then covers both actions
        one_time_job = force_one_time_job()
        resource = get_one_time_job_resource(one_time_job)
        self.assertEqual(str(resource), f'Turbo::OneTimeJob::"{one_time_job.pk}"')
        parent, = resource.parents
        self.assertEqual(str(parent), f'Turbo::Configuration::"{one_time_job.configuration.pk}"')

    def test_the_row_carries_the_job_it_runs(self):
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(job=command.job)
        job = get_one_time_job_resource(one_time_job).attrs["job"]
        self.assertEqual(str(job), f'Turbo::Job::"{command.job.pk}"')
        self.assertEqual(job.attrs["kind"], "file_export")

    def test_the_job_type_is_registered(self):
        # If an attribute is an entity of an unregistered type, Cedar cannot resolve the whole
        # schema. Every policy save then fails, not only a save for this action.
        self.assertIn(("Job", "Turbo"), engine.entity_types)
        self.assertIn(("OneTimeJob", "Turbo"), engine.entity_types)

    def test_a_policy_can_read_the_job_through_the_row(self):
        # The row as the resource gives an update policy the job, and the entity is in the
        # slice, so Cedar resolves the dereference.
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"updateOneTimeJob",'
                                ' resource'
                                ') when { resource.job.kind == "sysdiagnose" };\n'})
        allowed = force_one_time_job(job=force_command(backend=CommandBackend.SYSDIAGNOSE).job)
        refused = force_one_time_job(job=force_command(backend=CommandBackend.FILE_EXPORT).job)
        self.assertTrue(self._authorized(UpdateOneTimeJobRequest(self.user, allowed)))
        self.assertFalse(self._authorized(UpdateOneTimeJobRequest(self.user, refused)))

    def test_a_configuration_scoped_policy_covers_the_row(self):
        allowed = force_configuration()
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"updateOneTimeJob",'
                                f' resource in Turbo::Configuration::"{allowed.pk}"'
                                ");\n"})
        inside = force_one_time_job(configuration=allowed)
        outside = force_one_time_job()
        self.assertTrue(self._authorized(UpdateOneTimeJobRequest(self.user, inside)))
        self.assertFalse(self._authorized(UpdateOneTimeJobRequest(self.user, outside)))

    def test_an_update_request_is_never_a_preview(self):
        one_time_job = force_one_time_job()
        self.assertFalse(UpdateOneTimeJobRequest(self.user, one_time_job).unknown_context)

    # the context

    def test_job_is_the_only_context_attribute(self):
        for action in self.ACTIONS:
            self.assertEqual(list(action.applies_to.context), ["job"])

    def test_the_context_job_is_an_entity(self):
        # An entity, not a kind string. context.job.kind gives what a job_kind key gives, and a
        # policy can read any other attribute of the job without a change to the actions.
        for action in self.ACTIONS:
            self.assertIs(action.applies_to.context["job"].type, JOB_RESOURCE_TYPE)

    def test_the_context_job_is_required(self):
        # The question before the operator picks a job is a preview. Its context is unknown, not
        # empty, so a policy that reads it residualizes and does not fail. No action declares the
        # attribute optional, and no policy needs a has guard.
        for action in self.ACTIONS:
            self.assertTrue(action.applies_to.context["job"].required)

    def test_the_job_kind_values_are_declared_on_the_job_type(self):
        # the schema browser shows the set of kinds on the entity
        self.assertEqual(sorted(JOB_RESOURCE_TYPE.attrs["kind"].values), sorted(Job.Kind.values))

    def test_a_request_without_a_job_is_a_preview(self):
        configuration = force_configuration()
        self.assertTrue(CreateOneTimeJobRequest(self.user, configuration).unknown_context)

    def test_a_request_with_a_job_is_not_a_preview(self):
        configuration = force_configuration()
        command = force_command()
        request = CreateOneTimeJobRequest(self.user, configuration, command.job)
        self.assertFalse(request.unknown_context)

    def test_a_request_without_a_job_carries_no_context(self):
        configuration = force_configuration()
        self.assertEqual(CreateOneTimeJobRequest(self.user, configuration).context, {})

    def test_a_request_with_a_job_carries_it_as_an_entity(self):
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        job = CreateOneTimeJobRequest(self.user, configuration, command.job).context["job"]
        self.assertEqual(str(job), f'Turbo::Job::"{command.job.pk}"')
        self.assertEqual(job.attrs["kind"], "file_export")

    def test_every_kind_reaches_the_context_as_a_declared_value(self):
        # a policy that compares a value from the schema browser must match the value sent
        configuration = force_configuration()
        values = JOB_RESOURCE_TYPE.attrs["kind"].values
        for job in (force_script().job, force_command(backend=CommandBackend.SYSDIAGNOSE).job,
                    force_command(backend=CommandBackend.FILE_EXPORT).job):
            request = CreateOneTimeJobRequest(self.user, configuration, job)
            self.assertIn(request.context["job"].attrs["kind"], values)

    # the actions

    def test_actions_carry_help_text(self):
        for action in self.ACTIONS:
            self.assertTrue(action.help_text)

    def test_actions_are_not_legacy_mapped(self):
        # the reason for the retirement: nothing can ask them with System and an empty context
        for perm in ("turbo.add_onetimejob", "turbo.change_onetimejob", "turbo.delete_onetimejob"):
            self.assertNotIn(perm, engine.legacy_perm_actions)

    def test_view_stays_legacy_mapped(self):
        # Not typed, deliberately. A typed view action must scope a list, which means a policy
        # filters a queryset instead of a decision on one request.
        self.assertIn("turbo.view_onetimejob", engine.legacy_perm_actions)
        self.assertNotIn(("viewOneTimeJob", "Turbo"), [
            (a_id, ns) for (a_id, ns), a in engine.actions.items()
            if a.applies_to is not LEGACY_PERM_APPLIES_TO
        ])

    def test_actions_stay_admin_only(self):
        for action in self.ACTIONS:
            self.assertEqual({p.id for p in action.parents}, {"AdminActions", "GlobalAdminActions"})

    def test_schedule_command_action_is_gone(self):
        self.assertNotIn(("scheduleCommand", "Turbo"), engine.actions)

    # decisions

    def test_denied_by_default(self):
        configuration = force_configuration()
        self.assertFalse(self._authorized(CreateOneTimeJobRequest(self.user, configuration)))

    def test_a_broad_grant_covers_both_questions(self):
        self._grant()
        configuration = force_configuration()
        command = force_command()
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, configuration)))
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, configuration, command.job)))

    def test_a_forbidden_kind_is_refused_and_the_others_are_not(self):
        self._grant()
        self._forbid_kind("file_export")
        configuration = force_configuration()
        refused = force_command(backend=CommandBackend.FILE_EXPORT)
        allowed = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.assertFalse(
            self._authorized(CreateOneTimeJobRequest(self.user, configuration, refused.job)))
        self.assertTrue(
            self._authorized(CreateOneTimeJobRequest(self.user, configuration, allowed.job)))

    def test_a_forbidden_kind_still_offers_the_action(self):
        # The preview keeps the console link available. A forbid that reads the job must not
        # refuse the question with no job. Partial evaluation residualizes it.
        self._grant()
        self._forbid_kind("file_export")
        configuration = force_configuration()
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, configuration)))

    def test_a_kind_scoped_permit_needs_no_guard_and_no_forbid(self):
        # The first policy that an operator writes. It permits one kind, and the console still
        # offers the action before the operator picks a job, because the preview cannot exclude
        # the permit. No has guard, and no second policy with a forbid.
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"createOneTimeJob",'
                                ' resource'
                                ') when { context.job.kind == "sysdiagnose" };\n'})
        configuration = force_configuration()
        allowed = force_command(backend=CommandBackend.SYSDIAGNOSE)
        refused = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, configuration)))
        self.assertTrue(
            self._authorized(CreateOneTimeJobRequest(self.user, configuration, allowed.job)))
        self.assertFalse(
            self._authorized(CreateOneTimeJobRequest(self.user, configuration, refused.job)))

    def test_a_preview_is_refused_when_no_policy_can_permit_it(self):
        # Deny is the only definitive answer of a preview: no context makes the request pass.
        # The console hides the action, and does not offer one that always fails.
        configuration = force_configuration()
        self.assertFalse(self._authorized(CreateOneTimeJobRequest(self.user, configuration)))

    def test_a_preview_is_refused_by_a_configuration_scoped_grant_elsewhere(self):
        # definitive for the same reason: the resource is known, and only the context is not
        allowed = force_configuration()
        other = force_configuration()
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"createOneTimeJob",'
                                f' resource == Turbo::Configuration::"{allowed.pk}"'
                                ') when { context.job.kind == "sysdiagnose" };\n'})
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, allowed)))
        self.assertFalse(self._authorized(CreateOneTimeJobRequest(self.user, other)))

    def test_a_grant_can_be_scoped_to_one_configuration(self):
        allowed = force_configuration()
        other = force_configuration()
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"createOneTimeJob",'
                                f' resource == Turbo::Configuration::"{allowed.pk}"'
                                ");\n"})
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, allowed)))
        self.assertFalse(self._authorized(CreateOneTimeJobRequest(self.user, other)))

    def test_a_kind_scoped_grant_reaches_a_script(self):
        # A policy governs every kind, not only the command kinds. A script runs any code as
        # root.
        self._grant()
        self._forbid_kind("script")
        configuration = force_configuration()
        script = force_script()
        command = force_command()
        self.assertFalse(self._authorized(CreateOneTimeJobRequest(self.user, configuration, script.job)))
        self.assertTrue(self._authorized(CreateOneTimeJobRequest(self.user, configuration, command.job)))

    def test_delete_is_refused_and_permitted_on_its_own(self):
        one_time_job = force_one_time_job()
        self.assertFalse(self._authorized(DeleteOneTimeJobRequest(self.user, one_time_job)))
        self._grant()
        self.assertTrue(self._authorized(DeleteOneTimeJobRequest(self.user, one_time_job)))

    def test_a_forbidden_kind_refuses_its_removal_too(self):
        # A delete stops the delivery of a schedule, so a policy for a kind governs the delete
        # too.
        self._grant()
        self._forbid_kind("file_export")
        refused = force_one_time_job(job=force_command(backend=CommandBackend.FILE_EXPORT).job)
        allowed = force_one_time_job(job=force_command(backend=CommandBackend.SYSDIAGNOSE).job)
        self.assertFalse(self._authorized(DeleteOneTimeJobRequest(self.user, refused)))
        self.assertTrue(self._authorized(DeleteOneTimeJobRequest(self.user, allowed)))

    def test_check_delete_raises_when_refused(self):
        one_time_job = force_one_time_job()
        with self.assertRaises(PermissionDenied):
            check_delete_one_time_job(self._FakeRequest(self.user), one_time_job)

    def test_the_context_job_is_in_the_entity_slice(self):
        # A policy that reads context.job.kind needs the job entity in the slice. Without it,
        # Cedar fails the dereference and the forbid permits the request.
        self._grant()
        Policy.objects.update_or_create(
            name="Turbo forbid",
            defaults={"source": "forbid ( principal,"
                                ' action == Turbo::Action::"createOneTimeJob",'
                                ' resource'
                                ') when { context.job.kind == "file_export" };\n'})
        configuration = force_configuration()
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        self.assertFalse(
            self._authorized(CreateOneTimeJobRequest(self.user, configuration, command.job)))

    def test_create_and_update_are_separate_actions(self):
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"createOneTimeJob",'
                                " resource"
                                ");\n"})
        one_time_job = force_one_time_job()
        self.assertTrue(
            self._authorized(CreateOneTimeJobRequest(self.user, one_time_job.configuration)))
        self.assertFalse(self._authorized(UpdateOneTimeJobRequest(self.user, one_time_job)))

    def test_one_policy_can_name_all_three_actions_through_the_context(self):
        # The reason that the job is in the context of all three actions: create has no row, so
        # one forbid for all three must use the context.
        self._grant()
        self._forbid_kind("file_export")
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        one_time_job = force_one_time_job(job=command.job)
        self.assertFalse(self._authorized(
            CreateOneTimeJobRequest(self.user, one_time_job.configuration, command.job)))
        self.assertFalse(self._authorized(UpdateOneTimeJobRequest(self.user, one_time_job)))
        self.assertFalse(self._authorized(DeleteOneTimeJobRequest(self.user, one_time_job)))

    # the checks and the console helpers

    def test_check_create_raises_when_refused(self):
        configuration = force_configuration()
        command = force_command()
        with self.assertRaises(PermissionDenied):
            check_create_one_time_job(self._FakeRequest(self.user), configuration, command.job)

    def test_check_create_passes_when_permitted(self):
        self._grant()
        configuration = force_configuration()
        command = force_command()
        check_create_one_time_job(self._FakeRequest(self.user), configuration, command.job)

    def test_check_update_raises_when_refused(self):
        one_time_job = force_one_time_job()
        with self.assertRaises(PermissionDenied):
            check_update_one_time_job(self._FakeRequest(self.user), one_time_job)

    def test_can_create_one_time_job(self):
        configuration = force_configuration()
        self.assertFalse(can_create_one_time_job(self.user, configuration))
        self._grant()
        self.assertTrue(can_create_one_time_job(self.user, configuration))

    def test_authorize_one_time_job_rows_decides_per_row(self):
        # the rows have different jobs, so one answer for the page is wrong
        self._grant()
        self._forbid_kind("file_export")
        configuration = force_configuration()
        refused = force_one_time_job(configuration=configuration,
                                     job=force_command(backend=CommandBackend.FILE_EXPORT).job)
        allowed = force_one_time_job(configuration=configuration,
                                     job=force_command(backend=CommandBackend.SYSDIAGNOSE).job)
        rows = authorize_one_time_job_rows(self.user, [refused, allowed])
        self.assertEqual([row.can_update for row in rows], [False, True])
        self.assertEqual([row.can_delete for row in rows], [False, True])

    def test_authorize_one_time_job_rows_pairs_the_decisions_per_row(self):
        # update and delete are separate actions, so a permit on one must not permit the other
        Policy.objects.update_or_create(
            name="Turbo grant",
            defaults={"source": "permit ("
                                f' principal in Role::"{self.group.pk}",'
                                ' action == Turbo::Action::"updateOneTimeJob",'
                                " resource"
                                ");\n"})
        rows = authorize_one_time_job_rows(self.user, [force_one_time_job(), force_one_time_job()])
        self.assertEqual([row.can_update for row in rows], [True, True])
        self.assertEqual([row.can_delete for row in rows], [False, False])

    def test_authorize_one_time_job_rows_with_no_rows(self):
        self.assertEqual(authorize_one_time_job_rows(self.user, []), [])
