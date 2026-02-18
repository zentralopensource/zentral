from django.test import TestCase
from django.utils.crypto import get_random_string

from zentral.contrib.mdm.models import RecoveryPasswordConfig


class TestMDMRecoveryPasswordConfigModel(TestCase):
    def test_no_static_password(self):
        rpc = RecoveryPasswordConfig.objects.create(
            name=get_random_string(12),
        )
        rpc.set_static_password(None)
        rpc.save()
        self.assertIsNone(rpc.static_password)
        self.assertIsNone(rpc.get_static_password())

    def test_static_password(self):
        rpc = RecoveryPasswordConfig.objects.create(
            name=get_random_string(12),
        )
        pwd = get_random_string(12)
        rpc.set_static_password(pwd)
        rpc.save()
        self.assertIsNotNone(rpc.static_password)
        self.assertEqual(rpc.get_static_password(), pwd)

    def test_rewrap_no_static_password(self):
        rpc = RecoveryPasswordConfig.objects.create(
            name=get_random_string(12),
        )
        rpc.rewrap_secrets()
        self.assertIsNone(rpc.static_password)
        self.assertIsNone(rpc.get_static_password())

    def test_rewrap_static_password(self):
        rpc = RecoveryPasswordConfig.objects.create(
            name=get_random_string(12),
        )
        pwd = get_random_string(12)
        rpc.set_static_password(pwd)
        rpc.save()
        rpc.rewrap_secrets()
        self.assertIsNotNone(rpc.static_password)
        self.assertEqual(rpc.get_static_password(), pwd)
