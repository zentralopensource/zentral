from datetime import datetime
from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.core.incidents.models import Incident, MachineIncident, Status, Severity
from zentral.core.probes.models import ProbeSource
from zentral.core.stores import frontend_store


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class InventoryViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        # probe
        cls.probe_source = ProbeSource.objects.create(
            model="BaseProbe",
            name=get_random_string(),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]}}
        )

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _force_incident(self, incident_type="probe", key=None, status=Status.OPEN, severity=Severity.CRITICAL):
        return Incident.objects.create(
            incident_type=incident_type,
            key={"probe_pk": self.probe_source.pk} if key is None else key,
            status=status.value,
            status_time=datetime.utcnow(),
            severity=severity.value,
        )

    def _force_machine_incident(self, incident, status=Status.OPEN):
        return MachineIncident.objects.create(
            serial_number=get_random_string(),
            incident=incident,
            status=status.value,
            status_time=datetime.utcnow(),
        )

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("incidents:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        self._login('incidents.view_incident')
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "0 Incidents")

    def test_index_with_one_incident(self):
        self._force_incident()
        self._login('incidents.view_incident')
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "1 Incident")
        self.assertContains(response, self.probe_source.name)

    # detail

    def test_incident_detail_redirect(self):
        incident = self._force_incident()
        self._login_redirect(reverse("incidents:incident", args=(incident.pk,)))

    def test_incident_detail_permission_denied(self):
        incident = self._force_incident()
        self._login()
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_detail_no_status_update(self):
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        self.assertNotContains(response, "Change status")

    def test_incident_detail_with_status_update(self):
        incident = self._force_incident()
        self._login("incidents.view_incident", "incidents.change_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        self.assertContains(response, "Change status")

    def test_incident_detail_no_perms_no_object_link(self):
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Probe")
        self.assertNotContains(response, self.probe_source.get_absolute_url())

    def test_incident_detail_perms_object_link(self):
        incident = self._force_incident()
        self._login("incidents.view_incident", "probes.view_probesource")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Probe")
        self.assertContains(response, self.probe_source.get_absolute_url())

    # update incident

    def test_update_incident_redirect(self):
        incident = self._force_incident()
        self._login_redirect(reverse("incidents:update_incident", args=(incident.pk,)))

    def test_update_incident_permission_denied(self):
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:update_incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_incident_get(self):
        incident = self._force_incident()
        self._login("incidents.view_incident", "incidents.change_incident")
        response = self.client.get(reverse("incidents:update_incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_form.html")

    def test_update_incident_post_error(self):
        incident = self._force_incident()
        self._login("incidents.view_incident", "incidents.change_incident")
        response = self.client.post(reverse("incidents:update_incident", args=(incident.pk,)),
                                    {"status": "YOLO"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_form.html")
        self.assertFormError(
            response, "form", "status",
            "Select a valid choice. YOLO is not one of the available choices."
        )

    def test_update_incident_post(self):
        incident = self._force_incident()
        self._login("incidents.view_incident", "incidents.change_incident")
        response = self.client.post(reverse("incidents:update_incident", args=(incident.pk,)),
                                    {"status": "IN_PROGRESS"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        incident.refresh_from_db()
        self.assertEqual(response.context["object"], incident)
        self.assertEqual(incident.status, "IN_PROGRESS")

    # incident events

    def test_incident_events_redirect(self):
        incident = self._force_incident()
        self._login_redirect(reverse("incidents:incident_events", args=(incident.pk,)))

    def test_incident_events_permission_denied(self):
        incident = self._force_incident()
        self._login()
        response = self.client.get(reverse("incidents:incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_events(self):
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_events.html")

    def test_fetch_incident_events_redirect(self):
        incident = self._force_incident()
        self._login_redirect(reverse("incidents:fetch_incident_events", args=(incident.pk,)))

    def test_fetch_incident_events_permission_denied(self):
        incident = self._force_incident()
        self._login()
        response = self.client.get(reverse("incidents:fetch_incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_incident_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:fetch_incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_incident_events_store_redirect_redirect(self):
        incident = self._force_incident()
        self._login_redirect(reverse("incidents:incident_events_store_redirect", args=(incident.pk,)))

    def test_incident_events_store_redirect_permission_denied(self):
        incident = self._force_incident()
        self._login()
        response = self.client.get(reverse("incidents:incident_events_store_redirect", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_events_store_redirect(self):
        incident = self._force_incident()
        self._login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident_events_store_redirect", args=(incident.pk,)),
                                   {"es": frontend_store.name})
        # dev store cannot redirect
        self.assertRedirects(response, reverse("incidents:incident_events", args=(incident.pk,)))

    # update machine incident

    def test_update_machine_incident_redirect(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self._login_redirect(reverse("incidents:update_machine_incident", args=(incident.pk, machine_incident.pk)))

    def test_update_machine_incident_permission_denied(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self._login("incidents.view_machineincident")
        response = self.client.get(reverse("incidents:update_machine_incident",
                                           args=(incident.pk, machine_incident.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_machine_incident_get(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self._login("incidents.change_machineincident")
        response = self.client.get(reverse("incidents:update_machine_incident",
                                           args=(incident.pk, machine_incident.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/machineincident_form.html")

    def test_update_machine_incident_post_error(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self._login("incidents.change_machineincident")
        response = self.client.post(reverse("incidents:update_machine_incident",
                                            args=(incident.pk, machine_incident.pk)),
                                    {"status": "YOLO"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/machineincident_form.html")
        self.assertFormError(
            response, "form", "status",
            "Select a valid choice. YOLO is not one of the available choices."
        )

    def test_update_machine_incident_post(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self._login("incidents.view_incident",
                    "incidents.change_machineincident")
        response = self.client.post(reverse("incidents:update_machine_incident",
                                            args=(incident.pk, machine_incident.pk)),
                                    {"status": "IN_PROGRESS"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        machine_incident.refresh_from_db()
        self.assertEqual(machine_incident.status, Status.IN_PROGRESS.value)
