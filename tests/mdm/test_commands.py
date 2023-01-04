import uuid
from datetime import datetime
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.declarations import update_blueprint_activation, update_blueprint_declaration_items
from zentral.contrib.mdm.models import (Blueprint,
                                        Channel, CommandStatus, RequestStatus,
                                        DEPEnrollmentSession,
                                        EnrolledDevice, EnrolledUser,
                                        PushCertificate)
from zentral.contrib.mdm.commands import DeviceInformation
from zentral.contrib.mdm.commands.utils import (_get_next_queued_command,
                                                _update_inventory)
from .utils import force_dep_enrollment, force_realm_user


class TestMDMCommands(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(32))
        push_certificate = PushCertificate.objects.create(
            name=get_random_string(64),
            topic=get_random_string(256),
            not_before=datetime(2000, 1, 1),
            not_after=datetime(2050, 1, 1),
            certificate=get_random_string(64).encode("utf-8"),
            private_key=get_random_string(64).encode("utf-8")
        )
        cls.blueprint1 = Blueprint.objects.create(name=get_random_string(32))
        update_blueprint_activation(cls.blueprint1, commit=False)
        update_blueprint_declaration_items(cls.blueprint1, commit=True)

        # Enrolled devices / user
        cls.enrolled_device_no_blueprint = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )
        cls.enrolled_device = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            blueprint=cls.blueprint1,
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )
        cls.enrolled_user = EnrolledUser.objects.create(
            enrolled_device=cls.enrolled_device,
            user_id=str(uuid.uuid4()).upper(),
            long_name=get_random_string(12),
            short_name=get_random_string(12),
            token=get_random_string(12).encode("utf-8"),
        )
        cls.enrolled_device_awaiting_configuration = EnrolledDevice.objects.create(
            push_certificate=push_certificate,
            serial_number=get_random_string(64),
            platform="macOS",
            blueprint=cls.blueprint1,
            dep_enrollment=True,
            awaiting_configuration=True,
            udid=get_random_string(36),
            token=get_random_string(32).encode("utf-8"),
            push_magic=get_random_string(73),
            unlock_token=get_random_string(32).encode("utf-8")
        )

        # DEP enrollment
        cls.dep_enrollment = force_dep_enrollment(cls.meta_business_unit)
        cls.dep_enrollment.realm, cls.realm_user = force_realm_user()
        cls.dep_enrollment.save()
        cls.dep_enrollment_session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            cls.dep_enrollment, cls.enrolled_device.serial_number, cls.enrolled_device.udid
        )
        cls.dep_enrollment_session.realm_user = cls.realm_user
        cls.dep_enrollment_session.save()
        es_request = EnrollmentSecret.objects.verify(
            "dep_enrollment_session",
            cls.dep_enrollment_session.enrollment_secret.secret,
            user_agent=get_random_string(12), public_ip_address="127.0.0.1"
        )
        cls.dep_enrollment_session.set_scep_verified_status(es_request)
        cls.dep_enrollment_session.set_authenticated_status(cls.enrolled_device)
        cls.dep_enrollment_session.set_completed_status(cls.enrolled_device)

    # _get_next_queued_command

    def test_no_next_queues_command(self):
        self.assertIsNone(_get_next_queued_command(
                Channel.Device, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None
        ))

    def test_device_information_not_queued(self):
        command = DeviceInformation.create_for_device(self.enrolled_device)
        self.assertEqual(command.enrolled_device, self.enrolled_device)
        self.assertIsNotNone(command.db_command.time)
        self.assertIsNone(_get_next_queued_command(
                Channel.Device, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None
        ))

    def test_queue_device_information(self):
        command = DeviceInformation.create_for_device(self.enrolled_device, queue=True)
        self.assertIsNone(command.db_command.time)
        fetched_command = _get_next_queued_command(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        )
        self.assertEqual(command, fetched_command)
        self.assertIsNone(_get_next_queued_command(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device_no_blueprint,
            None
        ))
        self.assertIsNone(_get_next_queued_command(
            Channel.User, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            self.enrolled_user
        ))

    def test_not_now_device_information_rescheduled(self):
        cmd = DeviceInformation.create_for_device(self.enrolled_device)
        cmd.db_command.status = CommandStatus.NotNow.value
        cmd.db_command.save()
        cmd2 = _get_next_queued_command(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None,
        )
        self.assertEqual(cmd, cmd2)

    # update inventory

    def test_update_inventory_not_now_noop(self):
        self.assertIsNone(
            _update_inventory(
                Channel.Device, RequestStatus.NotNow,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )

    def test_update_inventory_user_channel_noop(self):
        self.assertIsNone(
            _update_inventory(
                Channel.User, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                self.enrolled_user
            )
        )

    def test_update_inventory_no_blueprint_noop(self):
        self.assertIsNone(
            _update_inventory(
                Channel.Device, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device_no_blueprint,
                None
            )
        )

    def test_update_inventory_up_to_date(self):
        self.enrolled_device.device_information_updated_at = datetime.utcnow()
        self.enrolled_device.security_info_updated_at = datetime.utcnow()
        self.enrolled_device.blueprint.collect_apps = Blueprint.InventoryItemCollectionOption.ALL
        self.enrolled_device.blueprint.collect_certificates = Blueprint.InventoryItemCollectionOption.ALL
        self.enrolled_device.blueprint.collect_profiles = Blueprint.InventoryItemCollectionOption.ALL
        self.enrolled_device.apps_updated_at = datetime.utcnow()
        self.enrolled_device.certificates_updated_at = datetime.utcnow()
        self.enrolled_device.profiles_updated_at = datetime.utcnow()
        self.assertIsNone(
            _update_inventory(
                Channel.Device, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None,
            )
        )
