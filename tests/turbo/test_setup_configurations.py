from unittest.mock import patch
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import Configuration, Enrollment
from .utils import TurboSetupTestCase, force_configuration, force_enrollment, make_enrolled_machine


class TurboSetupConfigurationsTestCase(TurboSetupTestCase):
    # configuration list

    def test_configurations_redirect(self):
        self.login_redirect("configurations")

    def test_configurations_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_configurations(self):
        self.login("turbo.view_configuration")
        response = self.client.get(reverse("turbo:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_list.html")

    def test_configuration_enrollment_and_machine_count(self):
        self.login("turbo.view_configuration")
        configuration = force_configuration()
        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        make_enrolled_machine(enrollment)
        response = self.client.get(reverse("turbo:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["object_list"]), 1)
        self.assertEqual(response.context["object_list"][0].enrollment__count, 2)
        self.assertEqual(response.context["object_list"][0].enrollment__enrolledmachine__count, 3)

    def test_configurations_pagination(self):
        force_configuration()
        force_configuration()
        self.user.items_per_page = 1
        self.user.save()
        self.login("turbo.view_configuration")
        response = self.client.get(reverse("turbo:configurations"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["page_obj"].number, 2)
        self.assertIsNotNone(response.context.get("previous_url"))
        # pagination is rendered both above and below the table
        self.assertEqual(response.content.decode("utf-8").count('aria-label="Page navigation"'), 2)

    # configuration detail

    def test_configuration_detail(self):
        configuration = force_configuration()
        self.login("turbo.view_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        self.assertContains(response, configuration.name)

    def test_configuration_detail_no_enrollment_balanced_divs(self):
        # a config with no enrollments must not emit a stray </div> in the enrollment section
        configuration = force_configuration()
        self.login("turbo.view_configuration", "turbo.view_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        content = response.content.decode("utf-8")
        self.assertEqual(content.count("<div"), content.count("</div>"))

    def test_configuration_detail_enrollment_distributor(self):
        from tests.monolith.utils import force_manifest_enrollment_package
        from zentral.contrib.monolith.models import ManifestEnrollmentPackage
        configuration = force_configuration()
        enrollment = force_enrollment(configuration=configuration)
        # a Monolith enrollment package is a real enrollment distributor; point this enrollment's
        # distributor at one directly (.update() to skip save()'s package-rebuild callback)
        mep = force_manifest_enrollment_package()
        Enrollment.objects.filter(pk=enrollment.pk).update(
            distributor_content_type=ContentType.objects.get_for_model(ManifestEnrollmentPackage),
            distributor_pk=mep.pk)
        self.login("turbo.view_configuration", "turbo.view_enrollment",
                   "monolith.view_manifestenrollmentpackage")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, mep.get_description_for_enrollment())

    # create configuration

    def test_create_configuration_redirect(self):
        self.login_redirect("create_configuration")

    def test_create_configuration_permission_denied(self):
        self.login()
        response = self.client.get(reverse("turbo:create_configuration"))
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_get(self):
        self.login("turbo.add_configuration")
        response = self.client.get(reverse("turbo:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_configuration_post(self, post_event):
        self.login("turbo.add_configuration", "turbo.view_configuration")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:create_configuration"),
                                        {"name": name,
                                         "description": description,
                                         "collect_inventory": "on",
                                         "inventory_interval": 3600,
                                         "default_check_interval": 7200,
                                         "config_refresh_interval": 300,
                                         "results_batch_size": 50},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        configuration = response.context["object"]
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.inventory_interval, 3600)
        self.assertEqual(configuration.default_check_interval, 7200)
        self.assertEqual(configuration.config_refresh_interval, 300)
        self.assertEqual(configuration.results_batch_size, 50)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "turbo.configuration",
                 "pk": str(configuration.pk),
                 "new_value": {
                     "pk": configuration.pk,
                     "name": name,
                     "description": description,
                     "collect_inventory": True,
                     "inventory_interval": 3600,
                     "default_check_interval": 7200,
                     "config_refresh_interval": 300,
                     "results_batch_size": 50,
                     "created_at": configuration.created_at.isoformat(),
                     "updated_at": configuration.updated_at.isoformat(),
                 }}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"turbo_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["turbo", "zentral"])

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = force_configuration()
        self.login_redirect("update_configuration", configuration.pk)

    def test_update_configuration_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_get(self):
        configuration = force_configuration()
        self.login("turbo.change_configuration")
        response = self.client.get(reverse("turbo:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_configuration_post(self, post_event):
        configuration = force_configuration()
        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        enrollment_version = enrollment.version
        self.login("turbo.change_configuration", "turbo.view_configuration")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:update_configuration", args=(configuration.pk,)),
                                        {"name": new_name,
                                         "description": "",
                                         "collect_inventory": "on",
                                         "inventory_interval": 3600,
                                         "default_check_interval": 7200,
                                         "config_refresh_interval": 300,
                                         "results_batch_size": 50},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_detail.html")
        configuration2 = response.context["object"]
        self.assertEqual(configuration2, configuration)
        self.assertEqual(configuration2.name, new_name)
        self.assertEqual(configuration2.inventory_interval, 3600)
        # editing the configuration must not bump the enrollment version
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, enrollment_version)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["model"], "turbo.configuration")
        self.assertEqual(event.payload["object"]["pk"], str(configuration.pk))
        self.assertEqual(event.payload["object"]["prev_value"]["name"], configuration.name)
        self.assertEqual(event.payload["object"]["new_value"]["name"], new_name)

    # delete configuration

    def test_delete_configuration_redirect(self):
        configuration = force_configuration()
        self.login_redirect("delete_configuration", configuration.pk)

    def test_delete_configuration_permission_denied(self):
        configuration = force_configuration()
        self.login()
        response = self.client.get(reverse("turbo:delete_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_configuration_get(self):
        configuration = force_configuration()
        self.login("turbo.delete_configuration")
        response = self.client.get(reverse("turbo:delete_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_confirm_delete.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_configuration_post(self, post_event):
        configuration = force_configuration()
        pk = configuration.pk
        self.login("turbo.delete_configuration", "turbo.view_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("turbo:delete_configuration", args=(pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "turbo/configuration_list.html")
        self.assertEqual(Configuration.objects.filter(pk=pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        event = audit_events[0]
        self.assertEqual(event.payload["action"], "deleted")
        self.assertEqual(event.payload["object"]["model"], "turbo.configuration")
        self.assertEqual(event.payload["object"]["pk"], str(pk))

    def test_delete_configuration_with_enrollment_404(self):
        # the gate: a configuration with enrollments can't be deleted
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        self.login("turbo.delete_configuration")
        response = self.client.get(reverse("turbo:delete_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_configuration_detail_delete_button_hidden_with_enrollment(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        self.login("turbo.view_configuration", "turbo.delete_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_configuration", args=(configuration.pk,)))

    def test_configuration_detail_delete_button_shown_without_enrollment(self):
        configuration = force_configuration()
        self.login("turbo.view_configuration", "turbo.delete_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_configuration", args=(configuration.pk,)))

    def test_configuration_detail_enrollment_delete_button_shown_without_machine(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        self.login("turbo.view_configuration", "turbo.view_enrollment", "turbo.delete_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("turbo:delete_enrollment", args=(configuration.pk, enrollment.pk)))

    def test_configuration_detail_enrollment_delete_button_hidden_with_machine(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        configuration = enrollment.configuration
        make_enrolled_machine(enrollment)
        self.login("turbo.view_configuration", "turbo.view_enrollment", "turbo.delete_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("turbo:delete_enrollment", args=(configuration.pk, enrollment.pk)))
