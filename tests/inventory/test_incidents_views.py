from datetime import datetime
from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaMachine
from zentral.core.incidents.models import MachineIncident, Incident, Severity, Status
from zentral.core.probes.models import ProbeSource


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class InventoryIncidentsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # probe
        cls.probe_source = ProbeSource.objects.create(
            name=get_random_string(12),
            status=ProbeSource.ACTIVE,
            body={"filters": {"metadata": [{"event_types": ["inventory_heartbeat"]}]}}
        )
        # machine
        cls.serial_number = "0123456789"
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {"module": "tests.zentral.io", "name": "Zentral Tests"},
            "serial_number": cls.serial_number,
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ]
        })
        cls.machine = MetaMachine(cls.serial_number)
        cls.url_msn = cls.machine.get_urlsafe_serial_number()

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
            serial_number=self.serial_number,
            incident=incident,
            status=status.value,
            status_time=datetime.utcnow(),
        )

    # machine incidents

    def test_machine_incidents_redirect(self):
        self._login_redirect(reverse("inventory:machine_incidents", args=(self.url_msn,)))

    def test_machine_incidents_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:machine_incidents", args=(self.url_msn,)))
        self.assertEqual(response.status_code, 403)

    def test_machine_incidents_no_incident_links(self):
        incident = self._force_incident()
        self._force_machine_incident(incident)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_machineincident",
        )
        response = self.client.get(reverse("inventory:machine_incidents", args=(self.url_msn,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_incidents.html")
        self.assertContains(response, self.probe_source.name)
        self.assertNotContains(response, incident.get_absolute_url())

    def test_machine_incidents_incident_links(self):
        incident = self._force_incident()
        self._force_machine_incident(incident)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_incident",
            "incidents.view_machineincident",
        )
        response = self.client.get(reverse("inventory:machine_incidents", args=(self.url_msn,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_incidents.html")
        self.assertContains(response, self.probe_source.name)
        self.assertContains(response, incident.get_absolute_url())

    # open incidents

    def test_open_incidents_no_perms_no_open_incidents(self):
        incident = self._force_incident()
        self._force_machine_incident(incident)
        self._login(
            "inventory.view_machinesnapshot",
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(response, "Open incident (1)")
        self.assertNotContains(response, self.probe_source.name)
        self.assertNotContains(response, incident.get_absolute_url())

    def test_open_incidents_one_open_incidents_no_link(self):
        incident = self._force_incident()
        self._force_machine_incident(incident)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_machineincident",
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Open incident (1)")
        self.assertContains(response, self.probe_source.name)
        self.assertNotContains(response, incident.get_absolute_url())

    def test_open_incidents_one_open_incidents_with_link(self):
        incident = self._force_incident()
        self._force_machine_incident(incident)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_incident",
            "incidents.view_machineincident",
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Open incident (1)")
        self.assertContains(response, self.probe_source.name)
        self.assertContains(response, incident.get_absolute_url())

    def test_open_incidents_two_open_incidents_with_links(self):
        incident = self._force_incident(key={"probe_pk": 0})
        self._force_machine_incident(incident)
        incident2 = self._force_incident()
        self._force_machine_incident(incident2)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_incident",
            "incidents.view_machineincident",
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Open incidents (2)")
        self.assertContains(response, "Unknown probe incident")
        self.assertContains(response, self.probe_source.name)
        self.assertContains(response, incident.get_absolute_url())
        self.assertContains(response, incident2.get_absolute_url())

    def test_open_incidents_one_of_two_incidents_with_link(self):
        incident = self._force_incident(key={"probe_pk": 0}, status=Status.CLOSED)
        self._force_machine_incident(incident, status=Status.CLOSED)
        incident2 = self._force_incident()
        self._force_machine_incident(incident2)
        self._login(
            "inventory.view_machinesnapshot",
            "incidents.view_incident",
            "incidents.view_machineincident",
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Open incident (1)")
        self.assertNotContains(response, "Unknown probe incident")
        self.assertContains(response, self.probe_source.name)
        self.assertNotContains(response, incident.get_absolute_url())
        self.assertContains(response, incident2.get_absolute_url())
