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
