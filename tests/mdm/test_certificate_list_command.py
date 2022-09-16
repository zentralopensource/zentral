from datetime import datetime
import os.path
import plistlib
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit, MetaMachine
from zentral.contrib.mdm.commands import CertificateList
from zentral.contrib.mdm.inventory import commit_update_tree, tree_from_payload
from zentral.contrib.mdm.models import Blueprint
from .utils import force_dep_enrollment_session


class CertificateListCommandTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(
            name=get_random_string(32),
            collect_certificates=Blueprint.InventoryItemCollectionOption.ALL,
        )
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.device_information = plistlib.load(
            open(
                os.path.join(
                    os.path.dirname(__file__), "testdata/device_information.plist"
                ),
                "rb",
            )
        )
        cls.device_information["UDID"] = cls.enrolled_device.udid
        cls.device_information["SerialNumber"] = cls.enrolled_device.serial_number
        cls.certificate_list = plistlib.load(
            open(
                os.path.join(
                    os.path.dirname(__file__), "testdata/certificate_list.plist"
                ),
                "rb",
            )
        )

    def test_load_kwargs_store_result_false(self):
        cmd = CertificateList.create_for_device(
            self.enrolled_device,
            kwargs={"managed_only": True, "update_inventory": True},
        )
        self.assertTrue(cmd.managed_only)
        self.assertTrue(cmd.update_inventory)
        self.assertFalse(cmd.store_result)

    def test_load_kwargs_store_result_true(self):
        cmd = CertificateList.create_for_device(
            self.enrolled_device,
        )
        self.assertFalse(cmd.managed_only)
        self.assertFalse(cmd.update_inventory)
        self.assertTrue(cmd.store_result)

    def test_build_command(self):
        cmd = CertificateList.create_for_device(self.enrolled_device)
        response = cmd.build_http_response(self.dep_enrollment_session)
        payload = plistlib.loads(response.content)["Command"]
        self.assertEqual(payload["RequestType"], "CertificateList")
        self.assertFalse(payload["ManagedOnly"])

    def test_process_acknowledged_response_missing_cms(self):
        cmd = CertificateList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        cmd.process_response(
            self.certificate_list, self.dep_enrollment_session, self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertIsNone(self.enrolled_device.certificates_updated_at)
        m = MetaMachine(self.enrolled_device.serial_number)
        self.assertEqual(len(m.snapshots), 0)

    def test_process_acknowledged_response_do_not_collect_certificates(self):
        start = datetime.utcnow()
        ms_tree = tree_from_payload(
            self.enrolled_device.udid,
            self.enrolled_device.serial_number,
            self.mbu,
            self.device_information["QueryResponses"],
        )
        commit_update_tree(self.enrolled_device, ms_tree, missing_ok=True)
        m0 = MetaMachine(self.enrolled_device.serial_number)
        ms0 = m0.snapshots[0]
        self.assertEqual(ms0.certificates.count(), 0)
        cmd = CertificateList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        self.blueprint.collect_certificates = Blueprint.InventoryItemCollectionOption.NO
        self.blueprint.save()
        cmd.process_response(
            self.certificate_list, self.dep_enrollment_session, self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.certificates_updated_at > start)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        self.assertEqual(ms.certificates.count(), 0)

    def test_process_acknowledged_response_collect_certificates(self):
        start = datetime.utcnow()
        ms_tree = tree_from_payload(
            self.enrolled_device.udid,
            self.enrolled_device.serial_number,
            self.mbu,
            self.device_information["QueryResponses"],
        )
        commit_update_tree(self.enrolled_device, ms_tree, missing_ok=True)
        m0 = MetaMachine(self.enrolled_device.serial_number)
        ms0 = m0.snapshots[0]
        self.assertEqual(ms0.certificates.count(), 0)
        cmd = CertificateList.create_for_device(
            self.dep_enrollment_session.enrolled_device,
            kwargs={"update_inventory": True},
        )
        self.assertEqual(
            self.enrolled_device.blueprint.collect_certificates,
            Blueprint.InventoryItemCollectionOption.ALL,
        )
        cmd.process_response(
            self.certificate_list, self.dep_enrollment_session, self.mbu
        )
        cmd.db_command.refresh_from_db()
        self.assertIsNone(cmd.db_command.result)
        self.enrolled_device.refresh_from_db()
        self.assertTrue(self.enrolled_device.certificates_updated_at > start)
        m = MetaMachine(self.enrolled_device.serial_number)
        ms = m.snapshots[0]
        i = 0
        for certificate in ms.certificates.select_related("signed_by").all():
            i += 1
            self.assertEqual(
                certificate.serialize(),
                {
                    "common_name": "zentral",
                    "sha_1": "f373928e75dfa460726c92c3263e664816b504d5",
                    "signed_by": {
                        "common_name": "Zentral CA",
                        "organization": "Zentral",
                        "organizational_unit": "IT",
                    },
                    "valid_from": "2019-06-27T10:56:05",
                    "valid_until": "2029-06-24T10:56:05",
                },
            )
        self.assertEqual(i, 1)
