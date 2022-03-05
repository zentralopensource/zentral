import base64
import json
from unittest.mock import patch
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.wsone.models import Instance


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class WSOneEventNotificationsViewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()
        cls.instance = Instance.objects.create(
            business_unit=cls.bu,
            server_url="https://{}.example.com".format(get_random_string(8)),
            client_id=get_random_string(),
            token_url="https://{}.example.com".format(get_random_string(8)),
            username=get_random_string()
        )
        cls.instance.set_api_key(get_random_string())
        cls.instance.set_client_secret(get_random_string())
        cls.instance.set_password(get_random_string())
        cls.instance.save()
        cls.instance.refresh_from_db()

    # utils

    @staticmethod
    def build_event_notification(event_type):
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
            "OrganizationGroupName": "Zentral",
            "DeviceUUID": "7caaee42-5f19-4b51-8187-bd43f4484a65",
            "EnrollmentUserUUID": "a9b7786f-d537-440f-b68b-a58189c530d2"
        }

    @classmethod
    def build_compromised_status_changed_notification(cls):
        return cls.build_event_notification("Compromised Status Changed")

    @classmethod
    def build_device_operation_system_changed_notification(cls):
        return cls.build_event_notification("Device Operating System Changed")

    @classmethod
    def build_device_organization_group_changed_notification(cls):
        return cls.build_event_notification("Device Organization Group Changed")

    def make_request(
        self,
        auth=True, broken_auth=False,
        username=None, password=None,
        instance_pk=None,
        data=None,
        method="POST",
    ):
        instance_pk = instance_pk or self.instance.pk
        url = reverse("wsone:event_notifications", args=(instance_pk,))
        kwargs = {"content_type": "application/json"}
        if auth:
            username = username or self.instance.username
            password = password or self.instance.get_password()
            if broken_auth:
                scheme = "Broken"
            else:
                scheme = "BaSIc"
            kwargs["HTTP_AUTHORIZATION"] = "{} {}".format(
                scheme,
                base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            )
        if data:
            kwargs["data"] = json.dumps(data)
        if method == "POST":
            return self.client.post(url, **kwargs)
        elif method == "GET":
            return self.client.get(url, **kwargs)
        else:
            raise ValueError(f"Unsupported method {method}")

    # test Workspace ONE event notification *Test Connection*

    def test_wsone_test_error(self):
        response = self.make_request(auth=False, method="GET")
        self.assertEqual(response.status_code, 403)

    def test_wsone_test_ok(self):
        response = self.make_request(method="GET")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"OK")

    # test Workspace ONE event notifications

    def test_unknown_instance_not_found(self):
        response = self.make_request(instance_pk=self.instance.pk + 100,
                                     data=self.build_compromised_status_changed_notification())
        self.assertEqual(response.status_code, 404)

    def test_no_auth_header(self):
        response = self.make_request(auth=False,
                                     data=self.build_compromised_status_changed_notification())
        self.assertEqual(response.status_code, 403)

    def test_broken_auth_header(self):
        response = self.make_request(broken_auth=True,
                                     data=self.build_compromised_status_changed_notification())
        self.assertEqual(response.status_code, 403)

    def test_wrong_password(self):
        response = self.make_request(username="yolo", password="fomo",
                                     data=self.build_compromised_status_changed_notification())
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_compromised_status_changed_notification(self, post_raw_event):
        response = self.make_request(data=self.build_compromised_status_changed_notification())
        self.assertEqual(response.status_code, 200)
        # check posted raw event
        self.assertEqual(len(post_raw_event.call_args_list), 1)
        routing_key, raw_event = post_raw_event.call_args_list[0].args
        self.assertEqual(routing_key, "wsone_events")
        self.assertEqual(raw_event["request"]["ip"], "127.0.0.1")
        self.assertEqual(raw_event["observer"]["hostname"], self.instance.hostname)
        self.assertEqual(raw_event["wsone_event"]["DeviceId"], 10000)
        self.assertEqual(raw_event["wsone_event"]["EventType"], "Compromised Status Changed")
        self.assertEqual(raw_event["wsone_instance"]["pk"], self.instance.pk)
