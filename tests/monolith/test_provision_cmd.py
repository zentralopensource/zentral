from django.core.management import call_command
from django.test import TestCase
from zentral.contrib.monolith.models import Repository


class MonolithProvisionManagementCommandsTest(TestCase):

    # provisioning

    def test_repository_provisioning(self):
        qs = Repository.objects.all()
        self.assertEqual(qs.count(), 0)
        call_command('provision')
        self.assertEqual(qs.count(), 1)
        repository = qs.first()
        # see tests/conf/base.json
        self.assertEqual(repository.name, "YoloFomo")
        self.assertEqual(repository.backend, "VIRTUAL")
        self.assertEqual(repository.get_backend_kwargs(), {})
