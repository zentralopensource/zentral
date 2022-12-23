from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.commands import DeclarativeManagement
from zentral.contrib.mdm.commands.utils import _trigger_declarative_management_sync
from zentral.contrib.mdm.declarations import update_blueprint_activation, update_blueprint_declaration_items
from zentral.contrib.mdm.models import Blueprint, Channel, Platform, RequestStatus
from .utils import force_dep_enrollment_session, force_enrolled_user


class DeclarativeManagementCommandTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.dep_enrollment_session, _, _ = force_dep_enrollment_session(
            cls.mbu,
            authenticated=True,
            completed=True,
            realm_user=True
        )
        cls.enrolled_device = cls.dep_enrollment_session.enrolled_device
        cls.blueprint = Blueprint.objects.create(name=get_random_string(32))
        update_blueprint_activation(cls.blueprint, commit=False)
        update_blueprint_declaration_items(cls.blueprint, commit=True)
        cls.enrolled_device.blueprint = cls.blueprint
        cls.enrolled_device.save()

    # verify_channel_and_device

    def test_scope(self):
        for channel, platform, user_enrollment, os_version, result in (
            (Channel.Device, Platform.macOS, False, "13.1.0", True),
            (Channel.User, Platform.macOS, False, "13.1.0", False),
            (Channel.Device, Platform.macOS, False, "12.6.1", False),
            (Channel.Device, Platform.tvOS, False, "16.1", True),
            (Channel.User, Platform.tvOS, False, "16.1", False),
            (Channel.Device, Platform.tvOS, False, "15.1", False),
            (Channel.Device, Platform.iOS, True, "15.1", True),
            (Channel.User, Platform.iOS, True, "15.1", False),
            (Channel.Device, Platform.iOS, True, "14.1", False),
            (Channel.Device, Platform.iOS, False, "15.1", False),
            (Channel.Device, Platform.iOS, False, "16.1", True),
            (Channel.User, Platform.iOS, False, "16.1", False),
            (Channel.Device, Platform.iPadOS, True, "15.1", True),
            (Channel.User, Platform.iPadOS, True, "15.1", False),
            (Channel.Device, Platform.iPadOS, True, "14.1", False),
            (Channel.Device, Platform.iPadOS, False, "15.1", False),
            (Channel.Device, Platform.iPadOS, False, "16.1", True),
            (Channel.User, Platform.iPadOS, False, "16.1", False),
        ):
            self.enrolled_device.platform = platform.name
            self.enrolled_device.user_enrollment = user_enrollment
            self.enrolled_device.os_version = os_version
            self.assertEqual(
                result,
                DeclarativeManagement.verify_channel_and_device(
                    channel, self.enrolled_device
                )
            )

    # _trigger_declarative_management_sync

    def test_trigger_declarative_management_sync_notnow_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.enrolled_device.os_version = "13.1.0"
        self.assertIsNone(
            _trigger_declarative_management_sync(
                Channel.Device, RequestStatus.NotNow,
                self.dep_enrollment_session,
                self.enrolled_device,
                None
            )
        )

    def test_trigger_declarative_management_sync_no_declarative_management_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.assertFalse(self.enrolled_device.declarative_management)
        self.enrolled_device.os_version = "13.1.0"
        self.assertIsNotNone(self.enrolled_device.blueprint)
        cmd = _trigger_declarative_management_sync(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        )
        self.assertIsInstance(cmd, DeclarativeManagement)

    def test_trigger_declarative_management_sync_user_channel_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.enrolled_device.declarative_management = True
        self.enrolled_device.os_version = "13.1.0"
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.assertIsNone(
            _trigger_declarative_management_sync(
                Channel.User, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                force_enrolled_user(self.enrolled_device)
            )
        )

    def test_trigger_declarative_management_sync_no_blueprint_noop(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.enrolled_device.declarative_management = True
        self.enrolled_device.os_version = "13.1.0"
        self.enrolled_device.blueprint = None
        self.assertIsNone(
            _trigger_declarative_management_sync(
                Channel.Device, RequestStatus.Idle,
                self.dep_enrollment_session,
                self.enrolled_device,
                None
            )
        )

    def test_trigger_declarative_management_sync(self):
        self.assertIsNotNone(self.enrolled_device.blueprint)
        self.enrolled_device.declarative_management = True
        self.enrolled_device.os_version = "13.1.0"
        self.assertIsNotNone(self.enrolled_device.blueprint)
        cmd = _trigger_declarative_management_sync(
            Channel.Device, RequestStatus.Idle,
            self.dep_enrollment_session,
            self.enrolled_device,
            None
        )
        self.assertIsInstance(cmd, DeclarativeManagement)
