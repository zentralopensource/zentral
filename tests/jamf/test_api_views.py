import json
from django.urls import reverse
from django.test import TestCase, override_settings
from zentral.contrib.jamf.models import JamfInstance


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


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
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
