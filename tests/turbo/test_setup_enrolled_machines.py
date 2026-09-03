import json
import uuid

from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaMachine
from accounts.models import Policy
from zentral.contrib.turbo.command_backends import CommandBackend
from zentral.contrib.turbo.models import OneTimeJob, RecurringJobMachine
from .utils import (TurboSetupTestCase, forbid_job_kind_policy, force_command,
                    force_configuration, force_enrolled_machine, force_enrollment,
                    force_mscp_check, force_recurring_job, force_script, turbo_policy)


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
        self.login("turbo.view_enrolledmachine")
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
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)),
                                   {"kind": "mscp_check"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([m.recurring_job.job_id for m in response.context["recurring_job_machines"]],
                         [mscp_rj.job_id])

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
        # can see enrolled machines, but nothing grants the scheduling action
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_schedule_machine_one_time_job_permission_checked_before_lookup(self):
        # for someone who cannot see enrolled machines at all, an unknown serial returns 403 and not
        # 404: the response must not reveal whether the serial is enrolled. The scheduling action
        # cannot be the gate that runs first — its resource is the configuration, and that is only
        # known once the serial resolves — so turbo.view_enrolledmachine is.
        self.login()
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 403)

    def test_schedule_machine_one_time_job_unknown_serial(self):
        # with access to enrolled machines an unknown serial is an honest 404: someone holding
        # view_enrolledmachine can already list them, so there is nothing left to hide
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

    # PBAC: a forbid keyed on the job's kind refuses the schedule even though the role is granted
    # the action. The forbid rides on top of the broad grant turbo_policy() writes — one of two
    # shapes that work, the other being a kind-scoped permit on its own (pinned in test_pbac).

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
