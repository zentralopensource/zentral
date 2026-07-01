from unittest.mock import patch
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import Tag
from zentral.contrib.turbo.models import Enrollment
from .utils import TurboAPITestCase, force_configuration, force_enrollment, make_enrolled_machine


class TurboEnrollmentAPITestCase(TurboAPITestCase):
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_enrollment(self, post_event):
        configuration = force_configuration()
        self.set_permissions("turbo.add_enrollment")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:enrollments"),
                                 {"configuration": configuration.pk,
                                  "secret": {"meta_business_unit": self.mbu.pk}})
        self.assertEqual(response.status_code, 201)
        enrollment = Enrollment.objects.get(pk=response.json()["id"])
        self.assertEqual(enrollment.configuration, configuration)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "created")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.enrollment")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(metadata["objects"], {
            "turbo_enrollment": [str(enrollment.pk)],
            "turbo_configuration": [str(configuration.pk)],
        })

    def test_create_enrollment_with_secret_tags(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_permissions("turbo.add_enrollment")
        response = self.post(reverse("turbo_api:enrollments"),
                             {"configuration": configuration.pk,
                              "secret": {"meta_business_unit": self.mbu.pk, "tags": [tag.pk]}})
        self.assertEqual(response.status_code, 201)
        enrollment = Enrollment.objects.get(pk=response.json()["id"])
        self.assertEqual(set(enrollment.secret.tags.all()), {tag})

    def test_update_enrollment(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.set_permissions("turbo.change_enrollment")
        response = self.put(reverse("turbo_api:enrollment", args=(enrollment.pk,)),
                            {"configuration": enrollment.configuration.pk,
                             "secret": {"meta_business_unit": self.mbu.pk}})
        self.assertEqual(response.status_code, 200)

    def test_update_distributor_enrollment(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.distributor_content_type = ContentType.objects.get(app_label="monolith",
                                                                      model="manifestenrollmentpackage")
        enrollment.distributor_pk = 1  # invalid, only for this test, not the reason for the rejection
        super(Enrollment, enrollment).save()  # avoid the distributor callback
        self.set_permissions("turbo.change_enrollment")
        response = self.put(reverse("turbo_api:enrollment", args=(enrollment.pk,)),
                            {"configuration": enrollment.configuration.pk,
                             "secret": {"meta_business_unit": self.mbu.pk}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This enrollment cannot be updated"])

    def test_get_enrollment(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.set_permissions("turbo.view_enrollment")
        response = self.get(reverse("turbo_api:enrollment", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["enrolled_machines_count"], 0)
        self.assertTrue(data["configuration_profile_download_url"].endswith(
            reverse("turbo_api:enrollment_configuration_profile", args=(enrollment.pk,))))
        self.assertTrue(data["plist_download_url"].endswith(
            reverse("turbo_api:enrollment_plist", args=(enrollment.pk,))))

    def test_list_enrollments_annotates_machine_count(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        make_enrolled_machine(enrollment)
        force_enrollment(meta_business_unit=self.mbu)  # a second enrollment with no machines
        self.set_permissions("turbo.view_enrollment")
        with CaptureQueriesContext(connection) as ctx:
            response = self.get(reverse("turbo_api:enrollments"))
        self.assertEqual(response.status_code, 200)
        counts = {e["id"]: e["enrolled_machines_count"] for e in response.json()["results"]}
        self.assertEqual(counts[enrollment.pk], 2)
        # the count is annotated on the queryset, so there is no per-enrollment COUNT(*) on enrolledmachine
        per_row_counts = [q for q in ctx.captured_queries
                          if 'from "turbo_enrolledmachine"' in q["sql"].lower()]
        self.assertEqual(per_row_counts, [])

    def test_delete_enrollment(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        pk = enrollment.pk
        self.set_permissions("turbo.delete_enrollment")
        response = self.delete(reverse("turbo_api:enrollment", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Enrollment.objects.filter(pk=pk).count(), 0)

    def test_delete_enrollment_with_enrolled_machine(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        pk = enrollment.pk
        self.set_permissions("turbo.delete_enrollment")
        response = self.delete(reverse("turbo_api:enrollment", args=(pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This enrollment cannot be deleted"])
        self.assertEqual(Enrollment.objects.filter(pk=pk).count(), 1)
