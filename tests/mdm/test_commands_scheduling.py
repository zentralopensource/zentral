import uuid
from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.artifacts import Target
from zentral.contrib.mdm.commands import DeviceInformation
from zentral.contrib.mdm.commands.scheduling import (
    _get_next_queued_command,
    _update_base_inventory,
    _update_extra_inventory,
)
from zentral.contrib.mdm.models import (
    Blueprint,
    Command,
    RequestStatus,
    EnrolledUser,
)
from .utils import force_dep_enrollment_session


class TestMDMCommandsScheduling(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu, authenticated=True, completed=True, realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(name=get_random_string(12))
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )

    # _get_next_queued_command

    def test_no_next_queues_command(self):
        self.assertIsNone(
            _get_next_queued_command(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_device_information_not_queued(self):
        command = DeviceInformation.create_for_device(self.enrolled_device)
        self.assertEqual(command.enrolled_device, self.enrolled_device)
        self.assertIsNotNone(command.db_command.time)
        self.assertIsNone(
            _get_next_queued_command(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_queue_device_information(self):
        command = DeviceInformation.create_for_device(self.enrolled_device, queue=True)
        self.assertIsNone(command.db_command.time)
        fetched_command = _get_next_queued_command(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertEqual(command, fetched_command)
        self.assertIsNone(
            _get_next_queued_command(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_not_now_device_information_rescheduled(self):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        cmd.db_command.status = Command.Status.NOT_NOW
        cmd.db_command.save()
        cmd2 = _get_next_queued_command(
            Target(self.enrolled_device),
            self.dep_enrollment_session,
            RequestStatus.IDLE,
        )
        self.assertEqual(cmd, cmd2)

    # update inventory

    def test_update_base_inventory_not_now_noop(self):
        self.assertIsNone(
            _update_base_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.NOT_NOW,
            )
        )

    def test_update_extra_inventory_not_now_noop(self):
        self.assertIsNone(
            _update_extra_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.NOT_NOW,
            )
        )

    def test_update_base_inventory_user_channel_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.assertIsNone(
            _update_base_inventory(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_update_extra_inventory_user_channel_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.assertIsNone(
            _update_extra_inventory(
                Target(self.enrolled_device, self.enrolled_user),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_update_extra_inventory_no_blueprint_noop(self):
        self.enrolled_device.blueprint = None
        self.assertIsNone(
            _update_extra_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )

    def test_update_inventory_up_to_date(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = (
            Blueprint.InventoryItemCollectionOption.ALL
        )
        self.enrolled_device.blueprint.collect_certificates = (
            Blueprint.InventoryItemCollectionOption.ALL
        )
        self.enrolled_device.blueprint.collect_profiles = (
            Blueprint.InventoryItemCollectionOption.ALL
        )
        self.enrolled_device.apps_updated_at = datetime.utcnow()
        self.enrolled_device.certificates_updated_at = datetime.utcnow()
        self.enrolled_device.profiles_updated_at = datetime.utcnow()
        self.assertIsNone(
            _update_base_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )
        self.assertIsNone(
            _update_extra_inventory(
                Target(self.enrolled_device),
                self.dep_enrollment_session,
                RequestStatus.IDLE,
            )
        )
