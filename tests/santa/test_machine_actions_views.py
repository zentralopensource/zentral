from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaMachine
from zentral.contrib.santa.models import EnrolledMachine
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision

from .utils import force_enrolled_machine


class SantaMachineActionsViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # the machine page reads the admin console store. The store cache is a process-wide
        # singleton with its notifier sync disabled in the tests, so an earlier test that
        # loaded it before the stores existed has to be undone explicitly
        provision()
        stores.clear()
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "santa"

    # utils

    def set_clean_sync_policy(self, sync_type=None):
        """Grant forceCleanSync, alongside whatever the legacy perms policy already grants."""
        source = ("permit ("
                  f' principal in Role::"{self.group.pk}",'
                  ' action == Santa::Action::"forceCleanSync",'
                  "  resource"
                  ")")
        if sync_type:
            source += f' when {{ context.syncType == "{sync_type}" }}'
        Policy.objects.update_or_create(name="Santa tests", defaults={"source": source + ";\n"})

    def force_url(self, machine, sync_type="CLEAN"):
        return reverse("santa:force_machine_clean_sync",
                       args=(machine.get_urlsafe_serial_number(), sync_type))

    def cancel_url(self, machine):
        return reverse("santa:cancel_machine_clean_sync", args=(machine.get_urlsafe_serial_number(),))

    # force a clean sync

    def test_force_clean_sync_redirect(self):
        self.login_redirect("force_machine_clean_sync", "012345678", "CLEAN")

    def test_force_clean_sync_permission_denied(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        response = self.client.get(self.force_url(machine))
        self.assertEqual(response.status_code, 403)

    def test_force_clean_sync_machine_not_enrolled(self):
        self.login()
        self.set_clean_sync_policy()
        machine = MetaMachine(get_random_string(12))
        response = self.client.get(self.force_url(machine))
        self.assertEqual(response.status_code, 404)

    def test_force_clean_sync_unknown_sync_type(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy()
        # NORMAL is a sync type, but not one that can be queued
        response = self.client.get(self.force_url(machine, "NORMAL"))
        self.assertEqual(response.status_code, 404)
        response = self.client.get(self.force_url(machine, "CLEAN_RULES"))
        self.assertEqual(response.status_code, 404)

    def test_force_clean_sync_get(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy()
        response = self.client.get(self.force_url(machine, "CLEAN_ALL"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/force_machine_clean_sync_confirm.html")
        self.assertContains(response, "including the transitive rules")

    def test_force_clean_sync_get_clean_keeps_the_transitive_rules(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy()
        response = self.client.get(self.force_url(machine))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The rules Zentral synced with the machine are dropped first")
        self.assertNotContains(response, "including the transitive rules")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_clean_sync_post(self, post_event):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.force_url(machine, "CLEAN_ALL"), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "Clean all sync queued for machine")
        enrolled_machine.refresh_from_db()
        self.assertEqual(enrolled_machine.forced_sync_type, "CLEAN_ALL")
        self.assertIsNotNone(enrolled_machine.forced_sync_type_at)
        event = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)][-1]
        self.assertEqual(event.metadata.machine_serial_number, enrolled_machine.serial_number)
        self.assertIsNone(event.payload["object"]["prev_value"]["forced_sync_type"])
        self.assertEqual(event.payload["object"]["new_value"]["forced_sync_type"], "CLEAN_ALL")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_force_clean_sync_post_twice_posts_one_event(self, post_event):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        for _ in range(2):
            with self.captureOnCommitCallbacks(execute=True):
                self.client.post(self.force_url(machine), follow=True)
        audit_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]
        self.assertEqual(len(audit_events), 1)

    def test_force_clean_all_sync_denied_by_a_clean_only_policy(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy(sync_type="CLEAN")
        self.assertEqual(self.client.get(self.force_url(machine, "CLEAN_ALL")).status_code, 403)
        self.assertEqual(self.client.get(self.force_url(machine)).status_code, 200)

    # cancel a queued clean sync

    def test_cancel_clean_sync_get(self):
        enrolled_machine = force_enrolled_machine(forced_sync_type=EnrolledMachine.SyncType.CLEAN_ALL)
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy()
        response = self.client.get(self.cancel_url(machine))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/cancel_machine_clean_sync_confirm.html")
        self.assertContains(response, "clean all")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cancel_clean_sync_post(self, post_event):
        enrolled_machine = force_enrolled_machine(forced_sync_type=EnrolledMachine.SyncType.CLEAN)
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.cancel_url(machine), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Queued clean sync cancelled for machine")
        enrolled_machine.refresh_from_db()
        self.assertIsNone(enrolled_machine.forced_sync_type)
        self.assertIsNone(enrolled_machine.forced_sync_type_at)
        event = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)][-1]
        self.assertEqual(event.payload["object"]["prev_value"]["forced_sync_type"], "CLEAN")
        self.assertIsNone(event.payload["object"]["new_value"]["forced_sync_type"])

    def test_cancel_clean_all_sync_denied_by_a_clean_only_policy(self):
        enrolled_machine = force_enrolled_machine(forced_sync_type=EnrolledMachine.SyncType.CLEAN_ALL)
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login()
        self.set_clean_sync_policy(sync_type="CLEAN")
        # the cancellation is authorized against the sync type it takes back
        response = self.client.get(self.cancel_url(machine))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cancel_clean_sync_when_none_is_queued_posts_no_event(self, post_event):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(self.cancel_url(machine), follow=True)
        self.assertEqual(response.status_code, 200)
        audit_events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]
        self.assertEqual(len(audit_events), 0)

    # the machine action menu

    def test_machine_detail_actions_enabled(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(
            response,
            f'<a href="{self.force_url(machine)}" class="dropdown-item">Force clean sync</a>'
        )
        self.assertContains(
            response,
            f'<a href="{self.force_url(machine, "CLEAN_ALL")}"'
            ' class="dropdown-item text-danger">Force clean all sync</a>'
        )
        # nothing is queued, there is nothing to cancel
        self.assertContains(
            response,
            f'<a href="{self.cancel_url(machine)}" class="dropdown-item disabled">Cancel queued clean sync</a>'
        )

    def test_machine_detail_actions_with_a_queued_clean_sync(self):
        enrolled_machine = force_enrolled_machine(forced_sync_type=EnrolledMachine.SyncType.CLEAN)
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        response = self.client.get(machine.get_absolute_url())
        self.assertContains(
            response,
            f'<a href="{self.cancel_url(machine)}" class="dropdown-item">Cancel queued clean sync</a>'
        )
        # one is queued already, queueing another is not offered
        self.assertContains(
            response,
            f'<a href="{self.force_url(machine)}" class="dropdown-item disabled">Force clean sync</a>'
        )

    def test_machine_detail_actions_only_the_granted_sync_type(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy(sync_type="CLEAN")
        response = self.client.get(machine.get_absolute_url())
        self.assertContains(response, self.force_url(machine))
        # the machine action menu hides what the user may not do, it does not grey it out
        self.assertNotContains(response, self.force_url(machine, "CLEAN_ALL"))

    def test_machine_detail_no_actions_without_a_policy(self):
        enrolled_machine = force_enrolled_machine()
        machine = MetaMachine(enrolled_machine.serial_number)
        self.login("inventory.view_machinesnapshot")
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(response, self.force_url(machine))
        self.assertNotContains(response, self.cancel_url(machine))

    def test_machine_detail_no_actions_for_a_machine_without_santa(self):
        machine = MetaMachine(get_random_string(12))
        self.login("inventory.view_machinesnapshot")
        self.set_clean_sync_policy()
        response = self.client.get(machine.get_absolute_url())
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        # the PBAC request needs the machine, so an unenrolled one has no action at all
        self.assertNotContains(response, self.force_url(machine))
