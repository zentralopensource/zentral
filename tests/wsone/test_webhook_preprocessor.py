from datetime import datetime
from unittest.mock import MagicMock, patch
from django.utils.crypto import get_random_string
from django.test import TestCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.wsone.models import Instance
from zentral.contrib.wsone.preprocessors import get_preprocessors


@patch.multiple(
    "zentral.contrib.wsone.api_client.Client",
    get_device=MagicMock(return_value={}),  # empty device
    iter_groups=MagicMock(return_value=[{"Name": "Zentral", "Id": 0}]),
    iter_group_children=MagicMock(return_value=[{"Name": "dwekjdhwkdhe", "Id": {"Value": 1}}])
)
class WSOneWebhookPreprocessorTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()
        cls.instance = Instance.objects.create(
            business_unit=cls.bu,
            server_url="https://{}.example.com".format(get_random_string(8)),
            client_id=get_random_string(12),
            token_url="https://{}.example.com".format(get_random_string(8)),
            username=get_random_string(12),
            excluded_groups=["dwekjdhwkdhe", "019318012833018"]
        )
        cls.instance.set_api_key(get_random_string(12))
        cls.instance.set_client_secret(get_random_string(12))
        cls.instance.set_password(get_random_string(12))
        cls.instance.save()
        cls.instance.refresh_from_db()
        cls.preprocessor = list(get_preprocessors())[0]

    # utils

    @staticmethod
    def build_event_notification(event_type, organization_group_name=None):
        return {
            "EventId": 178,
            "EventType": event_type,
            "DeviceId": 10000,
            "DeviceFriendlyName": "yolo",
            "EnrollmentEmailAddress": "yolo@zentral.pro",
            "EnrollmentUserName": "yolo",
            "EventTime": "2022-01-16T09:13:59.5720125Z",
            "EnrollmentStatus": "Enrolled",
            "CompromisedStatus": "",
            "CompromisedTimeStamp": "2022-01-16T09:14:00.1020757Z",
            "ComplianceStatus": "Compliant",
            "PhoneNumber": "",
            "Udid": "D20E0F3D66AF4B92B31E1DA394DF1E88",
            "SerialNumber": "ZL6LTO7H27AB",
            "MACAddress": "000000000000",
            "DeviceIMEI": "",
            "EnrollmentUserId": 455002,
            "AssetNumber": "EEEEA2C78F6C41CD8339E729D648EA05",
            "Platform": "AppleOsX",
            "OperatingSystem": "11.6.1",
            "Ownership": "CorporateDedicated",
            "SIMMCC": "",
            "CurrentMCC": "",
            "OrganizationGroupName": "Zentral" if organization_group_name is None else organization_group_name,
            "DeviceUUID": "7caaee42-5f19-4b51-8187-bd43f4484a65",
            "EnrollmentUserUUID": "a9b7786f-d537-440f-b68b-a58189c530d2"
        }

    @classmethod
    def build_raw_event(cls, event_type, organization_group_name=None):
        return {
            "request": {"ip": "127.0.0.1", "user_agent": "test"},
            "observer": cls.instance.observer_dict(),
            "wsone_instance": {"pk": cls.instance.pk, "version": cls.instance.version},
            "wsone_event": cls.build_event_notification(event_type, organization_group_name),
        }

    @classmethod
    def build_compliance_status_changed_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Compliance Status Changed", organization_group_name)

    @classmethod
    def build_compromised_status_changed_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Compromised Status Changed", organization_group_name)

    @classmethod
    def build_device_mcc_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Device MCC", organization_group_name)

    @classmethod
    def build_device_operation_system_changed_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Device Operating System Changed", organization_group_name)

    @classmethod
    def build_device_organization_group_changed_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Device Organization Group Changed", organization_group_name)

    @classmethod
    def build_break_mdm_confirmed_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Break MDM Confirmed", organization_group_name)

    @classmethod
    def build_enrollment_complete_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("Enrollment Complete", organization_group_name)

    @classmethod
    def build_mdm_enrollment_complete_raw_event(cls, organization_group_name=None):
        return cls.build_raw_event("MDM Enrollment Complete", organization_group_name)

    # tests

    def test_compliance_status_changed_notification(self):
        raw_event = self.build_compliance_status_changed_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_compliance_status_changed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_compromised_status_changed_notification(self):
        raw_event = self.build_compromised_status_changed_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_compromised_status_changed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_device_mcc_notification(self):
        raw_event = self.build_device_mcc_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_mcc_changed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_device_operation_system_changed_notification(self):
        raw_event = self.build_device_operation_system_changed_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_os_changed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_device_organization_group_changed_notification(self):
        raw_event = self.build_device_organization_group_changed_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_organization_group_changed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_break_mdm_confirmed_notification(self):
        raw_event = self.build_break_mdm_confirmed_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_break_mdm_confirmed")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_enrollment_complete_notification(self):
        raw_event = self.build_enrollment_complete_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_enrollment_complete")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_mdm_enrollment_complete_notification(self):
        raw_event = self.build_mdm_enrollment_complete_raw_event()
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_mdm_enrollment_complete")
        self.assertEqual(event.metadata.machine_serial_number, "ZL6LTO7H27AB")
        self.assertEqual(event.metadata.observer.pk, self.instance.pk)
        self.assertEqual(event.get_linked_objects_keys(), {"wsone_instance": [(self.instance.pk,)]})

    def test_excluded_mdm_enrollment_complete_notification(self):
        raw_event = self.build_mdm_enrollment_complete_raw_event(organization_group_name="dwekjdhwkdhe")
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 0)

    def test_missing_event_time(self):
        raw_event = self.build_mdm_enrollment_complete_raw_event()
        raw_event["wsone_event"].pop("EventTime")
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertNotEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_mdm_enrollment_complete")

    def test_bad_event_time(self):
        raw_event = self.build_mdm_enrollment_complete_raw_event()
        raw_event["wsone_event"]["EventTime"] = "yolo"
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertNotEqual(event.metadata.created_at, datetime(2022, 1, 16, 9, 13, 59, 572012))
        self.assertEqual(event.metadata.event_type, "wsone_mdm_enrollment_complete")

    def test_event_time_too_short(self):
        raw_event = self.build_mdm_enrollment_complete_raw_event()
        raw_event["wsone_event"]["EventTime"] = "2022-03-09T05:52:06.39916Z"
        events = list(self.preprocessor.process_raw_event(raw_event))
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event.metadata.created_at, datetime(2022, 3, 9, 5, 52, 6, 399000))
        self.assertEqual(event.metadata.event_type, "wsone_mdm_enrollment_complete")
