from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import MachineJobStatus, OneTimeJob
from .utils import (TurboSetupTestCase, force_configuration, force_enrolled_machine,
                    force_mscp_check, force_recurring_job, force_script)


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

    def test_enrolled_machines_one_row_per_serial_latest_config(self):
        config1 = force_configuration()
        config2 = force_configuration()
        serial_number = get_random_string(12)
        force_enrolled_machine(configuration=config1, meta_business_unit=self.mbu, serial_number=serial_number)
        force_enrolled_machine(configuration=config2, meta_business_unit=self.mbu, serial_number=serial_number)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machines"), {"q": serial_number})
        object_list = response.context["object_list"]
        self.assertEqual(len(object_list), 1)
        self.assertEqual(object_list[0].enrollment.configuration, config2)

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

    def test_enrolled_machine_detail(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        recurring_job = force_recurring_job(configuration=configuration)
        MachineJobStatus.objects.create(serial_number=serial_number, job=recurring_job.job,
                                        seen_version=recurring_job.job.version)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrolledmachine_detail.html")
        self.assertContains(response, serial_number)
        self.assertContains(response, str(recurring_job.job.definition))
        self.assertEqual([mjs.job_id for mjs in response.context["machine_job_statuses"]],
                         [recurring_job.job_id])

    def test_enrolled_machine_detail_filter_by_kind(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script_job = force_recurring_job(configuration=configuration).job
        mscp_job = force_mscp_check().job
        MachineJobStatus.objects.create(serial_number=serial_number, job=script_job)
        MachineJobStatus.objects.create(serial_number=serial_number, job=mscp_job)
        self.login("turbo.view_enrolledmachine")
        response = self.client.get(reverse("turbo:enrolled_machine", args=(serial_number,)),
                                   {"kind": "mscp_check"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual([m.job_id for m in response.context["machine_job_statuses"]], [mscp_job.pk])

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
        self.login("turbo.add_onetimejob")
        response = self.client.get(
            reverse("turbo:schedule_machine_one_time_job", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_schedule_machine_one_time_job_bad_window(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script = force_script()
        self.login("turbo.add_onetimejob")
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(script.job.pk), "not_before": "2026-07-02 10:00", "not_after": "2026-07-01 10:00"})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["form"], "not_after", "not_after must be on or after not_before")

    # schedule one-time job

    def test_schedule_machine_one_time_job_permission_denied(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.view_enrolledmachine")  # missing turbo.add_onetimejob
        response = self.client.get(reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 403)

    def test_schedule_machine_one_time_job_get(self):
        _, serial_number, _ = force_enrolled_machine(meta_business_unit=self.mbu)
        self.login("turbo.add_onetimejob")
        response = self.client.get(reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/machineonetimejob_form.html")

    def test_schedule_machine_one_time_job_post(self):
        configuration = force_configuration()
        _, serial_number, _ = force_enrolled_machine(configuration=configuration, meta_business_unit=self.mbu)
        script = force_script()
        self.login("turbo.add_onetimejob", "turbo.view_enrolledmachine")
        response = self.client.post(
            reverse("turbo:schedule_machine_one_time_job", args=(serial_number,)),
            {"job": str(script.job.pk)}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrolledmachine_detail.html")
        one_time_job = OneTimeJob.objects.get(job=script.job, configuration=configuration)
        self.assertEqual(one_time_job.serial_numbers, [serial_number])
        self.assertEqual(one_time_job.tags.count(), 0)
