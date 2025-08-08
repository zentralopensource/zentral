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
from zentral.contrib.osquery.compliance_checks import sync_query_compliance_check
from zentral.contrib.osquery.models import Query
from zentral.core.compliance_checks.models import MachineStatus, Status
from zentral.utils.provisioning import provision


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class InventoryComplianceChecksViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
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

    def _force_check_query(self):
        sql = "select 'OK' as ztl_status;"
        query = Query.objects.create(name=get_random_string(12), sql=sql)
        sync_query_compliance_check(query, True)
        return query

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

    # machine

    def test_machine_no_compliance_checks(self):
        self._force_check_query()
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'osquery.view_query',
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Compliance checks (0)")  # no status

    def test_machine_one_compliance_check_other_machine(self):
        query = self._force_check_query()
        MachineStatus.objects.create(
            serial_number=get_random_string(12),  # no the tested machine
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime.utcnow()
        )
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'osquery.view_query',
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Compliance checks (0)")

    def test_machine_one_compliance_check(self):
        query = self._force_check_query()
        MachineStatus.objects.create(
            serial_number=self.machine.serial_number,
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime.utcnow()
        )
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'osquery.view_query',
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Compliance check (1)")
        self.assertContains(response, query.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(query.compliance_check.pk,))
        self.assertContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], cc_redirect_link)
        self.assertEqual(compliance_check_statuses[0][1], query.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.OK)

    def test_machine_one_compliance_check_no_perms(self):
        query = self._force_check_query()
        MachineStatus.objects.create(
            serial_number=self.machine.serial_number,
            compliance_check=query.compliance_check,
            compliance_check_version=query.compliance_check.version,
            status=Status.FAILED.value,
            status_time=datetime.utcnow()
        )
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            # 'osquery.view_query', will block the link
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Compliance check (1)")
        self.assertContains(response, query.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(query.compliance_check.pk,))
        self.assertNotContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertIsNone(compliance_check_statuses[0][0])
        self.assertEqual(compliance_check_statuses[0][1], query.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.FAILED)
