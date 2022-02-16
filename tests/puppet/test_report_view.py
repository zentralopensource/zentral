import json
from unittest.mock import patch
import uuid
from django.core import signing
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.puppet.conf import puppet_conf
from zentral.utils.api_views import API_SECRET


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class PuppetReportViewTestCase(TestCase):
    @staticmethod
    def build_report():
        return {
            'cached_catalog_status': 'not_used',
            'catalog_uuid': str(uuid.uuid4()),
            'code_id': 'urn:puppet:code-id:1:{};development'.format(str(uuid.uuid4()).replace("-", "")),
            'configuration_version': 'pe-master.example.com-development-{}'.format(get_random_string(8)),
            'corrective_change': False,
            'environment': 'development',
            'host': get_random_string(),
            'master_used': 'pe-master.example.com:8140',
            'noop': False,
            'noop_pending': False,
            'puppet_version': '7.12.1',
            'report_format': 12,
            'server_used': 'pe-master.example.com:8140',
            'status': 'unchanged',
            'time': '2022-02-16T17:37:47.337045569Z',
            'transaction_completed': True,
            'transaction_uuid': str(uuid.uuid4())
        }

    def make_request(
        self,
        url,
        data=None,
        method="POST",
    ):
        kwargs = {"content_type": "application/json"}
        if data:
            kwargs["data"] = json.dumps(data)
        if method == "POST":
            return self.client.post(url, **kwargs)
        elif method == "GET":
            return self.client.get(url, **kwargs)
        else:
            raise ValueError(f"Unsupported method {method}")

    # test puppet report webhook

    def test_forbidden(self):
        response = self.make_request(reverse("puppet:post_report", args=("123",)), data=self.build_report())
        self.assertEqual(response.status_code, 403)

    def test_not_found(self):
        secret = signing.dumps({"url": "https://example.com"}, key=API_SECRET)
        response = self.make_request(reverse("puppet:post_report", args=(secret,)), data=self.build_report())
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_ok(self, post_raw_event):
        puppetdb_url = list(puppet_conf.instances.keys())[0]
        secret = signing.dumps({"url": puppetdb_url}, key=API_SECRET)
        response = self.make_request(reverse("puppet:post_report", args=(secret,)), data=self.build_report())
        self.assertEqual(response.status_code, 200)
        # check posted raw event
        self.assertEqual(len(post_raw_event.call_args_list), 1)
        routing_key, raw_event = post_raw_event.call_args_list[0].args
        self.assertEqual(routing_key, "puppet_reports")
        self.assertEqual(raw_event["request"]["ip"], "127.0.0.1")
        self.assertEqual(raw_event["event_type"], "puppet_report")
        self.assertEqual(raw_event["puppetdb_url"], puppetdb_url)
        self.assertEqual(raw_event["puppet_report"]["time"], "2022-02-16T17:37:47.337045569Z")
        self.assertIsNone(raw_event["puppet_report"].get("logs"))
