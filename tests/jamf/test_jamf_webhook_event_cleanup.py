from django.test import SimpleTestCase
from zentral.contrib.jamf.preprocessors import WebhookEventPreprocessor


class TestJamfWebhookEventCleanup(SimpleTestCase):
    def test_jamf_webhook_event_cleanup(self):
        d = {
            "un": 1,
            "deux": [{"un": 1, "deux": None}, {"trois": 3}],
            "trois": [],
            "quatre": [1, 2, 3, 4],
            "cinq": {"un": 1, "deux": None},
            "six": "6 ",
            "sept": "",
            "huit": {},
            "neuf": None,
            "dix": "              "
        }
        wep = WebhookEventPreprocessor()
        wep.cleanup_jamf_event(d)
        self.assertEqual(
            {"un": 1,
             "deux": [{"un": 1}, {"trois": 3}],
             "trois": [],
             "quatre": [1, 2, 3, 4],
             "cinq": {"un": 1},
             "six": "6"}, d
        )
