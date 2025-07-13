from django.core.management import call_command
from django.test import TestCase
from accounts.models import ProvisionedRole
from zentral.contrib.mdm.models import PushCertificate, SCEPConfig
from zentral.contrib.monolith.models import Repository
from zentral.core.stores.models import Store


class ProvisionBaseManagementCommandsTest(TestCase):
    def test_provision(self):
        expected_objects = (
            (ProvisionedRole, ("first-role", "second-role")),
            (PushCertificate, ("Default",)),
            (SCEPConfig, ("test",)),
            (Repository, ("test",)),
            (Store, ("elasticsearch",)),
        )
        # first call to trigger the creations
        call_command('provision')
        for model, provisioning_uids in expected_objects:
            self.assertEqual(
                model.objects.filter(provisioning_uid__in=provisioning_uids).count(),
                len(provisioning_uids)
            )
        # second call to trigger the updates
        call_command('provision')
        for model, provisioning_uids in expected_objects:
            self.assertEqual(
                model.objects.filter(provisioning_uid__in=provisioning_uids).count(),
                len(provisioning_uids)
            )
        self.assertEqual(
            set(
                r.provisioned_role.provisioning_uid
                for r in Store.objects.get(provisioning_uid="elasticsearch").events_url_authorized_roles.all()
            ),
            {"first-role"}
        )
