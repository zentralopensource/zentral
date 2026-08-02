from django.test import SimpleTestCase

from zentral.utils.drf import ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit
from zentral.utils.views import (AuditViewMixin, CreateViewWithAudit, DeleteViewWithAudit,
                                 UpdateViewWithAudit)


class AuditViewHookTestCase(SimpleTestCase):
    """get_audit_machine_serial_number() has to default to None on every audit view, so that
    the views whose audited object does not belong to a machine keep working untouched."""

    def test_every_audit_view_has_the_hook(self):
        for view_class in (CreateViewWithAudit, UpdateViewWithAudit, DeleteViewWithAudit,
                           ListCreateAPIViewWithAudit, RetrieveUpdateDestroyAPIViewWithAudit):
            with self.subTest(view_class.__name__):
                self.assertIsNone(view_class().get_audit_machine_serial_number())

    def test_the_django_audit_views_share_the_mixin(self):
        for view_class in (CreateViewWithAudit, UpdateViewWithAudit, DeleteViewWithAudit):
            with self.subTest(view_class.__name__):
                self.assertTrue(issubclass(view_class, AuditViewMixin))

    def test_an_override_is_picked_up(self):
        class MachineScopedView(CreateViewWithAudit):
            def get_audit_machine_serial_number(self):
                return "0123456789"

        self.assertEqual(MachineScopedView().get_audit_machine_serial_number(), "0123456789")
