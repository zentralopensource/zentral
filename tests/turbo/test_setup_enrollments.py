import plistlib
from unittest.mock import patch
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from zentral.contrib.turbo.models import Enrollment
from zentral.contrib.turbo.utils import build_configuration_profile
from zentral.utils.payloads import get_payload_identifier
from .utils import TurboSetupTestCase, force_configuration, force_enrollment, make_enrolled_machine


class TurboSetupEnrollmentsTestCase(TurboSetupTestCase):
    # create enrollment

    def test_create_enrollment_redirect(self):
        configuration = force_configuration()
        self.login_redirect("create_enrollment", configuration.pk)

    def test_create_enrollment_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_get(self):
        configuration = force_configuration()
        self.login("turbo.add_enrollment")
        response = self.client.get(reverse("turbo:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrollment_form.html")
        self.assertContains(response, "Turbo enrollment")

    def test_create_enrollment_invalid(self):
        configuration = force_configuration()
        self.login("turbo.add_enrollment")
        response = self.client.post(reverse("turbo:create_enrollment", args=(configuration.pk,)), {})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrollment_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_enrollment_post(self, post_event):
        configuration = force_configuration()
        self.login("turbo.add_enrollment", "turbo.view_configuration", "turbo.view_enrollment")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:create_enrollment", args=(configuration.pk,)),
                                        {"configuration": configuration.pk,
                                         "secret-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        enrollment = response.context["enrollments"][0][0]
        self.assertEqual(enrollment.configuration, configuration)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "turbo.enrollment")
        self.assertEqual(event.payload["object"]["pk"], str(enrollment.pk))
        # the enrollment event carries the configuration with keys_only=True
        self.assertEqual(event.payload["object"]["new_value"]["configuration"],
                         {"pk": configuration.pk, "name": configuration.name})
        # both the enrollment and the configuration are linked objects
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {
            "turbo_enrollment": [str(enrollment.pk)],
            "turbo_configuration": [str(configuration.pk)],
        })

    # bump enrollment version

    def test_bump_enrollment_version_redirect(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login_redirect("bump_enrollment_version", enrollment.configuration.pk, enrollment.pk)

    def test_bump_enrollment_version_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login()
        response = self.client.get(reverse("turbo:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_bump_enrollment_version_get(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login("turbo.change_enrollment")
        response = self.client.get(reverse("turbo:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrollment_confirm_version_bump.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_bump_enrollment_version_post(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        version = enrollment.version
        self.login("turbo.change_enrollment", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:bump_enrollment_version",
                                                args=(enrollment.configuration.pk, enrollment.pk)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, version + 1)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["model"], "turbo.enrollment")
        config_keys_only = {"pk": enrollment.configuration.pk, "name": enrollment.configuration.name}
        self.assertEqual(event.payload["object"]["prev_value"]["configuration"], config_keys_only)
        self.assertEqual(event.payload["object"]["new_value"]["configuration"], config_keys_only)
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {
            "turbo_enrollment": [str(enrollment.pk)],
            "turbo_configuration": [str(enrollment.configuration.pk)],
        })

    def test_bump_enrollment_version_distributor_404(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.distributor_content_type = ContentType.objects.get(app_label="monolith",
                                                                      model="manifestenrollmentpackage")
        enrollment.distributor_pk = 1  # invalid, only for this test, not the reason for the 404
        super(Enrollment, enrollment).save()  # avoid the distributor callback
        self.login("turbo.change_enrollment")
        response = self.client.get(reverse("turbo:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 404)

    # delete enrollment

    def test_delete_enrollment_redirect(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login_redirect("delete_enrollment", enrollment.configuration.pk, enrollment.pk)

    def test_delete_enrollment_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login()
        response = self.client.get(reverse("turbo:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_get(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login("turbo.delete_enrollment")
        response = self.client.get(reverse("turbo:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/enrollment_confirm_delete.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_enrollment_post(self, post_event):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        pk = enrollment.pk
        self.login("turbo.delete_enrollment", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:delete_enrollment", args=(configuration.pk, pk)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertEqual(Enrollment.objects.filter(pk=pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "deleted")
        self.assertEqual(event.payload["object"]["model"], "turbo.enrollment")
        self.assertEqual(event.payload["object"]["prev_value"]["configuration"],
                         {"pk": configuration.pk, "name": configuration.name})
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {
            "turbo_enrollment": [str(pk)],
            "turbo_configuration": [str(configuration.pk)],
        })

    def test_delete_enrollment_distributor_404(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.distributor_content_type = ContentType.objects.get(app_label="monolith",
                                                                      model="manifestenrollmentpackage")
        enrollment.distributor_pk = 1  # invalid, only for this test, not the reason for the 404
        super(Enrollment, enrollment).save()  # avoid the distributor callback
        self.login("turbo.delete_enrollment")
        response = self.client.get(reverse("turbo:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 404)

    def test_delete_enrollment_with_enrolled_machine_404(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        self.login("turbo.delete_enrollment")
        response = self.client.get(reverse("turbo:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 404)

    # enrollment configuration downloads

    def test_enrollment_plist_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login()
        response = self.client.get(reverse("turbo_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_plist(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login("turbo.view_enrollment")
        response = self.client.get(reverse("turbo_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/x-plist")
        self.assertEqual(response["Content-Disposition"],
                         f'attachment; filename="zentral_turbo_configuration.enrollment_{enrollment.pk}.plist"')
        content = b"".join(response.streaming_content)
        self.assertEqual(int(response["Content-Length"]), len(content))
        data = plistlib.loads(content)
        self.assertEqual(data["EnrollmentSecret"], enrollment.secret.secret)
        self.assertIn("BaseURL", data)
        self.assertNotIn("ManagedAgents", data)

    @patch("zentral.contrib.turbo.api_views.enrollments.build_configuration_plist")
    def test_enrollment_plist_filename_with_quote_escaped(self, build_plist):
        # FileResponse escapes a " in the filename instead of letting it break the header
        build_plist.return_value = ('weird".plist', b"<plist/>")
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login("turbo.view_enrollment")
        response = self.client.get(reverse("turbo_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="weird\\".plist"')

    def test_enrollment_configuration_profile_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login()
        response = self.client.get(reverse("turbo_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_enrollment_configuration_profile(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self.login("turbo.view_enrollment")
        response = self.client.get(reverse("turbo_api:enrollment_configuration_profile", args=(enrollment.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "application/octet-stream")
        identifier = get_payload_identifier("turbo_configuration")
        self.assertEqual(response["Content-Disposition"],
                         f'attachment; filename="{identifier}.mobileconfig"')
        content = b"".join(response.streaming_content)
        self.assertEqual(int(response["Content-Length"]), len(content))

    @patch("zentral.contrib.turbo.utils.sign_payload", side_effect=lambda payload: payload)
    def test_configuration_profile_flat_payload(self, _sign):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        _, content = build_configuration_profile(enrollment)
        payload = plistlib.loads(content)["PayloadContent"][0]
        # modern flat custom-settings payload: keys directly on the com.zentral.turbo payload
        self.assertEqual(payload["PayloadType"], "com.zentral.turbo")
        self.assertEqual(payload["EnrollmentSecret"], enrollment.secret.secret)
        self.assertIn("BaseURL", payload)
        self.assertNotIn("PayloadContent", payload)
        self.assertNotIn("mcx_preference_settings", content.decode("utf-8"))

    def test_configuration_detail_download_links(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        self.login("turbo.view_configuration", "turbo.view_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo_api:enrollment_plist", args=(enrollment.pk,)))
        self.assertContains(response, reverse("turbo_api:enrollment_configuration_profile", args=(enrollment.pk,)))
