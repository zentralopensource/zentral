from datetime import datetime
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.incidents.models import Incident, MachineIncident, Status, Severity
from zentral.core.probes.models import ProbeSource
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


class InventoryViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)
        # probe
        cls.probe_source = ProbeSource.objects.create(
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]}}
        )

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "incidents"

    # utility methods

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
            serial_number=get_random_string(12),
            incident=incident,
            status=status.value,
            status_time=datetime.utcnow(),
        )

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 403)

    def test_index(self):
        self.login('incidents.view_incident')
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "Incidents (0)")

    def test_index_with_one_incident(self):
        self._force_incident()
        self.login('incidents.view_incident')
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "Incident (1)")
        self.assertContains(response, self.probe_source.name)

    def test_index_search(self):
        self.login('incidents.view_incident')
        response = self.client.get(reverse("incidents:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertNotContains(response, "We didn't find any item related to your search")
        self._force_incident()
        response = self.client.get(reverse("incidents:index"), {"q": self.probe_source.name})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "Incident (1)")
        self.assertContains(response, self.probe_source.name)
        response = self.client.get(reverse("incidents:index"), {"q": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/index.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("incidents:index") + '">all the items')

    # detail

    def test_incident_detail_redirect(self):
        incident = self._force_incident()
        self.login_redirect("incident", incident.pk)

    def test_incident_detail_permission_denied(self):
        incident = self._force_incident()
        self.login()
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_detail_no_status_update(self):
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        self.assertNotContains(response, "Edit Status")

    def test_incident_detail_with_status_update(self):
        incident = self._force_incident()
        self.login("incidents.view_incident", "incidents.change_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        self.assertContains(response, "Edit Status")

    def test_incident_detail_no_perms_no_object_link(self):
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Probe")
        self.assertNotContains(response, self.probe_source.get_absolute_url())

    def test_incident_detail_perms_object_link(self):
        incident = self._force_incident()
        self.login("incidents.view_incident", "probes.view_probesource")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Probe")
        self.assertContains(response, self.probe_source.get_absolute_url())

    def test_incident_detail_machine_incidents(self):
        incident = self._force_incident()
        for i in range(23):
            self._force_machine_incident(incident)
        self.login("incidents.view_incident", "incidents.view_machineincident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Machine incidents (23)")
        self.assertContains(response, "page 1 of 3")

    def test_incident_detail_machine_incidents_second_page(self):
        incident = self._force_incident()
        for i in range(23):
            self._force_machine_incident(incident)
        self.login("incidents.view_incident", "incidents.view_machineincident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)) + "?page=2")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Machine incidents (23)")
        self.assertContains(response, "page 2 of 3")

    def test_incident_detail_no_perm_no_machine_incidents(self):
        incident = self._force_incident()
        for i in range(23):
            self._force_machine_incident(incident)
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Machine incidents (23)")
        self.assertNotContains(response, "page 1 of 3")

    # update incident

    def test_update_incident_redirect(self):
        incident = self._force_incident()
        self.login_redirect("update_incident", incident.pk)

    def test_update_incident_permission_denied(self):
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:update_incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_incident_get(self):
        incident = self._force_incident()
        self.login("incidents.view_incident", "incidents.change_incident")
        response = self.client.get(reverse("incidents:update_incident", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_form.html")

    def test_update_incident_post_error(self):
        incident = self._force_incident()
        self.login("incidents.view_incident", "incidents.change_incident")
        response = self.client.post(reverse("incidents:update_incident", args=(incident.pk,)),
                                    {"status": "YOLO"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_form.html")
        self.assertFormError(
            response.context["form"], "status",
            "Select a valid choice. YOLO is not one of the available choices."
        )

    def test_update_incident_post(self):
        incident = self._force_incident()
        self.login("incidents.view_incident", "incidents.change_incident")
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
        self.login_redirect("incident_events", incident.pk)

    def test_incident_events_permission_denied(self):
        incident = self._force_incident()
        self.login()
        response = self.client.get(reverse("incidents:incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_events(self):
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_events.html")

    def test_fetch_incident_events_redirect(self):
        incident = self._force_incident()
        self.login_redirect("fetch_incident_events", incident.pk)

    def test_fetch_incident_events_permission_denied(self):
        incident = self._force_incident()
        self.login()
        response = self.client.get(reverse("incidents:fetch_incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_object_events")
    def test_fetch_incident_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:fetch_incident_events", args=(incident.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_incident_events_store_redirect_redirect(self):
        incident = self._force_incident()
        self.login_redirect("incident_events_store_redirect", incident.pk)

    def test_incident_events_store_redirect_permission_denied(self):
        incident = self._force_incident()
        self.login()
        response = self.client.get(reverse("incidents:incident_events_store_redirect", args=(incident.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_incident_events_store_redirect(self):
        incident = self._force_incident()
        self.login("incidents.view_incident")
        response = self.client.get(reverse("incidents:incident_events_store_redirect", args=(incident.pk,)),
                                   {"es": stores.admin_console_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # update machine incident

    def test_update_machine_incident_redirect(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self.login_redirect("update_machine_incident", incident.pk, machine_incident.pk)

    def test_update_machine_incident_permission_denied(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self.login("incidents.view_machineincident")
        response = self.client.get(reverse("incidents:update_machine_incident",
                                           args=(incident.pk, machine_incident.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_machine_incident_get(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self.login("incidents.change_machineincident")
        response = self.client.get(reverse("incidents:update_machine_incident",
                                           args=(incident.pk, machine_incident.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/machineincident_form.html")

    def test_update_machine_incident_post_error(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self.login("incidents.change_machineincident")
        response = self.client.post(reverse("incidents:update_machine_incident",
                                            args=(incident.pk, machine_incident.pk)),
                                    {"status": "YOLO"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/machineincident_form.html")
        self.assertFormError(
            response.context["form"], "status",
            "Select a valid choice. YOLO is not one of the available choices."
        )

    def test_update_machine_incident_post(self):
        incident = self._force_incident()
        machine_incident = self._force_machine_incident(incident)
        self.login("incidents.view_incident",
                   "incidents.change_machineincident")
        response = self.client.post(reverse("incidents:update_machine_incident",
                                            args=(incident.pk, machine_incident.pk)),
                                    {"status": "IN_PROGRESS"}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "incidents/incident_detail.html")
        machine_incident.refresh_from_db()
        self.assertEqual(machine_incident.status, Status.IN_PROGRESS.value)
