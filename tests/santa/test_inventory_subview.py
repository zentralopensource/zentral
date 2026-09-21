import datetime

from accounts.models import User
from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.santa.models import EnrolledMachine
from zentral.contrib.santa.views import InventoryMachineSubview

from .utils import force_enrolled_machine


class SantaInventoryMachineSubviewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))

    def render_for(self, enrolled_machine):
        return InventoryMachineSubview(enrolled_machine.serial_number, self.user).render()

    def test_rules_in_sync(self):
        enrolled_machine = force_enrolled_machine(last_sync_ok=True)
        self.assertIn('<span class="text-success">Yes</span>', self.render_for(enrolled_machine))

    def test_rules_not_in_sync(self):
        enrolled_machine = force_enrolled_machine(last_sync_ok=False)
        self.assertIn('<span class="text-danger">No</span>', self.render_for(enrolled_machine))

    def test_rules_in_sync_unknown(self):
        # a template cannot tell an unknown state from a mismatch
        enrolled_machine = force_enrolled_machine(last_sync_ok=None)
        self.assertIn('<span class="text-secondary">Unknown</span>', self.render_for(enrolled_machine))

    # the queued clean sync is reported, the machine actions are the ones that change it

    def test_no_queued_clean_sync(self):
        enrolled_machine = force_enrolled_machine()
        self.assertNotIn("Clean sync", self.render_for(enrolled_machine))

    def test_queued_clean_sync(self):
        enrolled_machine = force_enrolled_machine(forced_sync_type=EnrolledMachine.SyncType.CLEAN_ALL)
        response = self.render_for(enrolled_machine)
        self.assertIn("Clean all queued", response)
        self.assertIn("applied at the next preflight", response)

    # the current enrollment, and the older rows

    def test_one_enrollment(self):
        enrolled_machine = force_enrolled_machine()
        self.assertNotIn("older one", self.render_for(enrolled_machine))

    def test_current_enrollment_and_history(self):
        serial_number = get_random_string(12)
        current = force_enrolled_machine(serial_number=serial_number, santa_version="2026.7",
                                         last_preflight_at=datetime.datetime(2026, 9, 2, tzinfo=datetime.UTC))
        stale = force_enrolled_machine(serial_number=serial_number, santa_version="2024.5",
                                       last_preflight_at=datetime.datetime(2026, 9, 1, tzinfo=datetime.UTC))
        stale.save()
        response = self.render_for(current)
        self.assertIn("2026.7", response)
        self.assertNotIn("2024.5", response)
        self.assertIn("current, and 1 older one", response)
