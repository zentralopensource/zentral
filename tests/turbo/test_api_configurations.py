from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.turbo.models import Configuration
from .utils import TurboAPITestCase, force_configuration, force_enrollment


class TurboConfigurationAPITestCase(TurboAPITestCase):
    def test_create_configuration_unauthorized(self):
        response = self.post(reverse("turbo_api:configurations"),
                             {"name": get_random_string(12)}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_configuration_permission_denied(self):
        response = self.post(reverse("turbo_api:configurations"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_configuration(self, post_event):
        self.set_permissions("turbo.add_configuration")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.post(reverse("turbo_api:configurations"),
                                 {"name": name,
                                  "inventory_interval": 3600,
                                  "default_check_interval": 7200,
                                  "config_refresh_interval": 300})
        self.assertEqual(response.status_code, 201)
        configuration = Configuration.objects.get(name=name)
        self.assertEqual(configuration.config_refresh_interval, 300)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "created")
        self.assertEqual(audit_events[0].payload["object"]["model"], "turbo.configuration")
        metadata = audit_events[0].metadata.serialize()
        self.assertEqual(metadata["objects"], {"turbo_configuration": [str(configuration.pk)]})

    def test_list_configurations(self):
        configuration = force_configuration()
        self.set_permissions("turbo.view_configuration")
        response = self.get(reverse("turbo_api:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 1)
        self.assertEqual(response.json()["results"][0]["id"], str(configuration.pk))

    def test_get_configuration(self):
        configuration = force_configuration()
        self.set_permissions("turbo.view_configuration")
        response = self.get(reverse("turbo_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], configuration.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_configuration(self, post_event):
        configuration = force_configuration()
        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        enrollment_version = enrollment.version
        self.set_permissions("turbo.change_configuration")
        new_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.put(reverse("turbo_api:configuration", args=(configuration.pk,)),
                                {"name": new_name,
                                 "inventory_interval": 3600,
                                 "default_check_interval": 7200,
                                 "config_refresh_interval": 300})
        self.assertEqual(response.status_code, 200)
        configuration.refresh_from_db()
        self.assertEqual(configuration.name, new_name)
        # editing the configuration must not bump the enrollment version
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, enrollment_version)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "updated")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_configuration(self, post_event):
        configuration = force_configuration()
        pk = configuration.pk
        self.set_permissions("turbo.delete_configuration")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.delete(reverse("turbo_api:configuration", args=(pk,)))
        self.assertEqual(response.status_code, 204)
        self.assertEqual(Configuration.objects.filter(pk=pk).count(), 0)
        audit_events = self._audit_events(post_event)
        self.assertEqual(len(audit_events), 1)
        self.assertEqual(audit_events[0].payload["action"], "deleted")

    def test_delete_configuration_with_enrollment_blocked(self):
        configuration = force_configuration()
        force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        self.set_permissions("turbo.delete_configuration")
        response = self.delete(reverse("turbo_api:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertTrue(Configuration.objects.filter(pk=configuration.pk).exists())
