import json
from unittest.mock import patch
from django.urls import reverse
from django.test import TestCase
from zentral.contrib.jamf.models import JamfInstance
from zentral.core.events.base import EventObserver


COMPUTER_CHECKIN = {
    "userDirectoryID": "-1",
    "jssID": 1789,
    "serialNumber": "C07NEWKFJHEWL",
    "model": "Mac mini (Late 2014)",
    "username": "",
    "position": "",
    "room": "",
    "macAddress": "AC:23:23:23:23:23",
    "phone": "",
    "emailAddress": "",
    "osVersion": "10.10.3",
    "alternateMacAddress": "6C:40:23:B9:EB:79",
    "realName": "",
    "deviceName": "h17",
    "udid": "BAD0B9C4-7798-5BA5-91C8-E24E76F30597",
    "department": "",
    "building": "",
    "osBuild": "14B25"
}

PAYLOAD = {"webhook": {"webhookEvent": "ComputerCheckIn"},
           "event": COMPUTER_CHECKIN}

MOBILE_DEVICE_INVENTORY_COMPLETED = {
    "udid": "00008103-0000000000000001",
    "deviceName": "iPad",
    "version": "26.3",
    "model": "iPad Pro 11-inch (M4)",
    "bluetoothMacAddress": "",
    "wifiMacAddress": "AC:23:23:23:23:24",
    "imei": "",
    "icciID": "",
    "product": "",
    "serialNumber": "C02MOBILE0001",
    "userDirectoryID": "-1",
    "room": "",
    "osVersion": "26.3",
    "osBuild": "23D127",
    "modelDisplay": "iPad Pro 11-inch (M4)",
    "username": "",
    "jssID": 42,
    "ipAddress": "203.0.113.1",
    "mdmCommand": "MobileDeviceInventoryCompleted",
    "mdmCommandUUID": "11111111-2222-3333-4444-555555555555",
    "managementId": "66666666-7777-8888-9999-000000000000",
}


class JssAPIViewsTestCase(TestCase):
    def post_as_json(self, secret, data):
        return self.client.post(reverse("jamf:post_event", args=(secret,)),
                                json.dumps(data),
                                content_type="application/json")

    def test_secret_bad_secret(self):
        response = self.post_as_json("co", PAYLOAD)
        self.assertEqual(response.status_code, 403)

    def test_ok(self):
        jamf_instance = JamfInstance(host="yo.example.com",
                                     user="god", password="zilla")
        jamf_instance.save()
        response = self.post_as_json(jamf_instance.secret, PAYLOAD)
        self.assertEqual(response.status_code, 200)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_mobile_device_inventory_completed(self, post_raw_event):
        jamf_instance = JamfInstance.objects.create(host="yo.example.com",
                                                    user="god", password="zilla")
        response = self.post_as_json(jamf_instance.secret,
                                     {"webhook": {"webhookEvent": "MobileDeviceInventoryCompleted"},
                                      "event": MOBILE_DEVICE_INVENTORY_COMPLETED})
        self.assertEqual(response.status_code, 200)
        post_raw_event.assert_called_once()
        routing_key, raw_event = post_raw_event.call_args.args
        self.assertEqual(routing_key, "jamf_events")
        self.assertEqual(raw_event["event_type"], "jamf_mobile_device_inventory_completed")
        self.assertEqual(raw_event["device_type"], "mobile_device")
        self.assertEqual(raw_event["jamf_id"], 42)
        self.assertEqual(raw_event["serial_number"], "C02MOBILE0001")

    def test_event_observer_serialization(self):
        jamf_instance = JamfInstance.objects.create(host="yo.example.com",
                                                    user="god", password="zilla")
        self.assertEqual(
            jamf_instance.observer_dict(),
            {'content_type': 'jamf.jamfinstance',
             'hostname': 'yo.example.com',
             'pk': jamf_instance.pk,
             'product': 'Jamf Pro',
             'type': 'MDM',
             'vendor': 'Jamf'},
        )
        self.assertEqual(
            jamf_instance.observer_dict(),
            EventObserver.deserialize(jamf_instance.observer_dict()).serialize(),
        )

    def test_event_observer_str(self):
        jamf_instance = JamfInstance.objects.create(host="yo.example.com",
                                                    user="god", password="zilla")
        self.assertEqual(
            str(EventObserver.deserialize(jamf_instance.observer_dict())),
            'yo.example.com',
        )

    def test_event_observer_get_object(self):
        jamf_instance = JamfInstance.objects.create(host="yo.example.com",
                                                    user="god", password="zilla")
        self.assertEqual(
            EventObserver.deserialize(jamf_instance.observer_dict()).get_object(),
            jamf_instance,
        )

    def test_event_observer_get_object_gone(self):
        jamf_instance = JamfInstance.objects.create(host="yo.example.com",
                                                    user="god", password="zilla")
        observer_dict = jamf_instance.observer_dict()
        jamf_instance.delete()
        self.assertIsNone(EventObserver.deserialize(observer_dict).get_object())
