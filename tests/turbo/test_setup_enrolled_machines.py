import json
import uuid

from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaMachine
from accounts.models import Policy
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import OneTimeJob, OneTimeJobMachine, RecurringJobMachine
from .utils import (VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION, TurboSetupTestCase,
                    forbid_job_kind_policy, force_command, force_configuration, force_enrolled_machine,
                    force_enrollment, force_mscp_check, force_one_time_job, force_recurring_job, force_script,
                    turbo_policy)


JOB_MACHINE_ACTIONS = ('Turbo::Action::"viewOneTimeJobMachine"', 'Turbo::Action::"viewRecurringJobMachine"')


class TurboSetupEnrolledMachinesTestCase(TurboSetupTestCase):
    # list

    def test_enrolled_machines_redirect(self):
        self.login_redirect("enrolled_machines")

    def test_enrolled_machines_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:enrolled_machines"))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_machines(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrolledmachine_list.html")
        self.assertContains(response, serial_number)

    def test_enrolled_machines_search_by_serial(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"q": serial_number})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([em.serial_number for em in response.context["object_list"]], [serial_number])

    def test_enrolled_machines_filter_by_configuration(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        force_enrolled_machine(meta_business_unit=self.mbu)  # a different configuration
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([em.serial_number for em in response.context["object_list"]], [serial_number])

    def test_enrolled_machines_search_no_result_shows_empty_results(self):
        force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"q": get_random_string(20)})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(list(response.context["object_list"]), [])
        self.assertContains(response, "We didn't find any item")

    def test_enrolled_machines_one_row_per_serial_current_config(self):
        # enrolling deletes the serial's superseded rows, so the list shows one row per serial,
        # on its current configuration
        serial_number = get_random_string(12)
        enrollments = [force_enrollment(meta_business_unit=self.mbu) for _ in range(2)]
        for enrollment in enrollments:
            response = self.client.post(
                reverse("turbo_public:enroll"),
                data=json.dumps({"secret": enrollment.secret.secret,
                                 "serial_number": serial_number,
                                 "hardware_uuid": str(uuid.uuid4())}),
                content_type="application/json",
            )
            self.assertEqual(response.status_code, 200)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"q": serial_number})
        object_list = response.context["object_list"]
        self.assertEqual(len(object_list), 1)
        self.assertEqual(object_list[0].enrollment.configuration, enrollments[1].configuration)

    # detail

    def test_enrolled_machine_permission_denied(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login()
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_enrolled_machine_not_found(self):
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machine", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_enrolled_machine_bad_urlsafe_serial_number_not_found(self):
        # a hand-crafted url-safe value that does not decode is a 404, not a 500
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machine", args=(".not-valid-base64!!",)))
        self.assertEqual(response.status_code, 404)

    def test_enrolled_machine_serial_with_slash(self):
        # a serial containing "/" is agent-supplied and cannot ride a <str:> URL segment raw; the list
        # links it url-safe and the detail page resolves it back, instead of 500ing on NoReverseMatch
        configuration = force_configuration()
        serial_number = "AB/CD"
        force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu,
                               serial_number=serial_number)
        urlsafe = MetaMachine.make_urlsafe_serial_number(serial_number)
        self.assertTrue(urlsafe.startswith("."))
        self.login("turbo.view_enrolledmachine")
        list_response = self.client.get(reverse("turbo:enrolled_machines"))
        self.assertEqual(list_response.status_code, 200)
        self.assertContains(list_response, serial_number)
        detail_response = self.client.get(reverse("turbo:enrolled_machine", args=(urlsafe,)))
        self.assertEqual(detail_response.status_code, 200)
        self.assertEqual(detail_response.context["serial_number"], serial_number)

    def test_enrolled_machine_detail(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        recurring_job = force_recurring_job(configuration=configuration)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=recurring_job,
                                           seen_version=recurring_job.job.version)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                            actions=JOB_MACHINE_ACTIONS))
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrolledmachine_detail.html")
        self.assertContains(response, serial_number)
        self.assertContains(response, str(recurring_job.job.definition))
        self.assertEqual([rjm.recurring_job.job_id for rjm in response.context["recurring_job_machines"]],
                         [recurring_job.job_id])

    def test_enrolled_machine_detail_filter_by_kind(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script_rj = force_recurring_job(configuration=configuration)
        mscp_rj = force_recurring_job(configuration=configuration, job=force_mscp_check().job)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=script_rj)
        RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=mscp_rj)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine",
                                            actions=JOB_MACHINE_ACTIONS))
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)),
                                   {"kind": "mscp_check"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([m.recurring_job.job_id for m in response.context["recurring_job_machines"]],
                         [mscp_rj.job_id])

    # a job state needs its own view, and nothing else

    def _machine_with_job_states(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        other_configuration = force_configuration()
        schedules = {}
        for schedule_configuration in (configuration, other_configuration):
            one_time_job = force_one_time_job(configuration=schedule_configuration)
            OneTimeJobMachine.objects.create(serial_number=serial_number, one_time_job=one_time_job)
            recurring_job = force_recurring_job(configuration=schedule_configuration)
            RecurringJobMachine.objects.create(serial_number=serial_number, recurring_job=recurring_job)
            schedules[schedule_configuration] = (one_time_job, recurring_job)
        return serial_number, configuration, other_configuration, schedules

    def _get_job_states(self, serial_number):
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        return (response,
                [otjm.one_time_job for otjm in response.context["one_time_job_machines"]],
                [rjm.recurring_job for rjm in response.context["recurring_job_machines"]])

    def test_enrolled_machine_detail_job_states_without_a_view_policy(self):
        serial_number, _, _, schedules = self._machine_with_job_states()
        self.login("turbo.view_enrolledmachine")
        response, one_time_jobs, recurring_jobs = self._get_job_states(serial_number)
        self.assertEqual(one_time_jobs, [])
        self.assertEqual(recurring_jobs, [])
        self.assertContains(response, "One-time (0)")
        self.assertContains(response, "Recurring (0)")
        for one_time_job, recurring_job in schedules.values():
            self.assertNotContains(response, str(one_time_job.job.definition))
            self.assertNotContains(response, str(recurring_job.job.definition))

    def test_enrolled_machine_detail_only_the_visible_job_states(self):
        serial_number, configuration, _, schedules = self._machine_with_job_states()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=())
            + turbo_policy(self.group, actions=JOB_MACHINE_ACTIONS,
                           condition=f'resource in Turbo::Configuration::"{configuration.pk}"')
        )
        response, one_time_jobs, recurring_jobs = self._get_job_states(serial_number)
        one_time_job, recurring_job = schedules[configuration]
        self.assertEqual(one_time_jobs, [one_time_job])
        self.assertEqual(recurring_jobs, [recurring_job])
        self.assertContains(response, "One-time (1)")
        self.assertContains(response, "Recurring (1)")

    def test_enrolled_machine_detail_job_states_without_the_view_of_the_schedule(self):
        # one action decides each state: the view of its schedule is another decision
        serial_number, _, _, schedules = self._machine_with_job_states()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=JOB_MACHINE_ACTIONS)
            + f"forbid (principal, action in [{VIEW_ONE_TIME_JOB_ACTION}, {VIEW_RECURRING_JOB_ACTION}], resource);\n"
        )
        _, one_time_jobs, recurring_jobs = self._get_job_states(serial_number)
        self.assertCountEqual(one_time_jobs, [one_time_job for one_time_job, _ in schedules.values()])
        self.assertCountEqual(recurring_jobs, [recurring_job for _, recurring_job in schedules.values()])

    def test_enrolled_machine_detail_job_states_need_their_own_view(self):
        serial_number, configuration, _, schedules = self._machine_with_job_states()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine",
                         actions=(VIEW_ONE_TIME_JOB_ACTION, VIEW_RECURRING_JOB_ACTION))
            + turbo_policy(self.group, actions=JOB_MACHINE_ACTIONS,
                           condition=f'resource in Turbo::Configuration::"{configuration.pk}"')
        )
        _, one_time_jobs, recurring_jobs = self._get_job_states(serial_number)
        one_time_job, recurring_job = schedules[configuration]
        self.assertEqual(one_time_jobs, [one_time_job])
        self.assertEqual(recurring_jobs, [recurring_job])

    def test_enrolled_machine_detail_job_states_one_decision_for_each_row(self):
        # like is not in the SQL subset: the same rows, with one decision for each state
        serial_number, configuration, _, schedules = self._machine_with_job_states()
        self.login_with_policy(
            turbo_policy(self.group, "turbo.view_enrolledmachine", actions=())
            + turbo_policy(self.group, actions=JOB_MACHINE_ACTIONS,
                           condition=f'resource in Turbo::Configuration::"{configuration.pk}" '
                                     '&& resource.job.kind like "*"')
        )
        _, one_time_jobs, recurring_jobs = self._get_job_states(serial_number)
        one_time_job, recurring_job = schedules[configuration]
        self.assertEqual(one_time_jobs, [one_time_job])
        self.assertEqual(recurring_jobs, [recurring_job])

    def test_enrolled_machines_pagination_reset_link(self):
        force_enrolled_machine(meta_business_unit=self.mbu)
        force_enrolled_machine(meta_business_unit=self.mbu)
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.context.get("reset_link"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

    def test_schedule_machine_one_time_job_not_found(self):
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_schedule_machine_one_time_job_bad_window(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script = force_script()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(script.job.pk), "not_before": "2026-07-02 10:00", "not_after": "2026-07-01 10:00"})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "not_after", "not_after must be on or after not_before")

    # schedule one-time job

    def test_schedule_machine_one_time_job_permission_denied(self):
        # can read the enrolled machines, but no policy permits the scheduling action
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_schedule_machine_one_time_job_permission_checked_before_lookup(self):
        # A user who cannot read the enrolled machines gets a 403 for an unknown serial
        # number, not a 404. The response must not tell the user if the serial number is
        # enrolled. The scheduling action cannot be the first gate, because its resource is the
        # configuration, and Zentral knows it only after it resolves the serial number. So
        # turbo.view_enrolledmachine is the first gate.
        self.login()
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 403)

    def test_schedule_machine_one_time_job_unknown_serial(self):
        # A user with access to the enrolled machines gets a 404 for an unknown serial number.
        # view_enrolledmachine gives the list of them, so the 404 tells the user nothing new.
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_schedule_machine_one_time_job_get(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.get(reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/machineonetimejob_form.html")

    def test_schedule_machine_one_time_job_post(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script = force_script()
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(script.job.pk)}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrolledmachine_detail.html")
        one_time_job = OneTimeJob.objects.get(job=script.job, configuration=configuration)
        self.assertEqual(one_time_job.serial_numbers, [serial_number])
        self.assertEqual(one_time_job.tags.count(), 0)

    # PBAC: a forbid on the kind of the job refuses the schedule, although the role has the
    # action. The forbid is above the broad permit of turbo_policy(). This is one of the two
    # shapes that work. The other is a permit for one kind, alone. See test_pbac.

    def _forbid_kind(self, kind):
        Policy.objects.create(name="Turbo kind forbid", source=forbid_job_kind_policy(kind))

    def test_schedule_machine_one_time_job_refused_by_a_forbidden_kind(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.FILE_EXPORT)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        self._forbid_kind("file_export")
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(command.job.pk)})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 0)

    def test_schedule_machine_one_time_job_allowed_for_another_kind(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        command = force_command(backend=CommandBackend.SYSDIAGNOSE)
        self.login_with_policy(turbo_policy(self.group, "turbo.view_enrolledmachine"))
        self._forbid_kind("file_export")
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(command.job.pk)}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(OneTimeJob.objects.filter(job=command.job).count(), 1)
