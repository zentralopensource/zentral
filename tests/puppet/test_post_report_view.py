import json
from unittest.mock import patch
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.puppet.models import Instance, delete_from_cache, update_cache
from .utils import build_report, build_self_signed_cert


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage'
)
class PuppetPostReportViewTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()
        cls.instance = Instance.objects.create(
            business_unit=cls.bu,
            url="https://{}.example.com".format(get_random_string(8)),
            ca_chain=build_self_signed_cert("CA")[0]
        )
        cls.instance.set_rbac_token(get_random_string())
        cls.token = get_random_string()
        cls.instance.set_report_processor_token(cls.token)
        cls.instance.save()
        cls.instance.refresh_from_db()

    def make_request(
        self,
        url,
        data=None,
        json_data=None,
        auth_header=None,
        method="POST",
    ):
        kwargs = {"content_type": "application/json"}
        if auth_header:
            kwargs["HTTP_AUTHORIZATION"] = auth_header
        if json_data:
            kwargs["data"] = json.dumps(json_data)
        elif data:
            kwargs["data"] = data
        if method == "POST":
            return self.client.post(url, **kwargs)
        elif method == "GET":
            return self.client.get(url, **kwargs)
        else:
            raise ValueError(f"Unsupported method {method}")

    # test puppet report webhook

    def test_bad_method(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            auth_header=f"Token {self.token}",
            method="GET",
        )
        self.assertEqual(response.status_code, 405)

    def test_missing_authorization_header(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            json_data=build_report(),
        )
        self.assertContains(response, "Missing Authorization header", status_code=403)

    def test_invalid_authorization_header(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            json_data=build_report(),
            auth_header="Bearer 123"
        )
        self.assertContains(response, "Invalid Authorization header", status_code=403)

    def test_instance_not_found(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk + 17,)),
            json_data=build_report(),
            auth_header="Token 123"
        )
        self.assertEqual(response.status_code, 404)

    def test_invalid_token(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            json_data=build_report(),
            auth_header="Token 123"
        )
        self.assertContains(response, "Invalid token", status_code=403)

    def test_invalid_report(self):
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            data="yolo",
            auth_header=f"Token {self.token}"
        )
        self.instance.refresh_from_db()
        self.assertContains(response, "Could not parse report", status_code=400)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_cache_hit_ok(self, post_raw_event):
        # update cache to ensure hit
        update_cache(self.instance)
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            json_data=build_report(),
            auth_header=f"Token {self.token}"
        )
        self.assertEqual(response.status_code, 200)
        # check posted raw event
        self.assertEqual(len(post_raw_event.call_args_list), 1)
        routing_key, raw_event = post_raw_event.call_args_list[0].args
        self.assertEqual(routing_key, "puppet_reports")
        self.assertEqual(raw_event["request"]["ip"], "127.0.0.1")
        self.assertEqual(raw_event["observer"]["pk"], self.instance.pk)
        self.assertEqual(raw_event["puppet_instance"], {"pk": self.instance.pk, "version": self.instance.version})
        self.assertEqual(raw_event["puppet_report"]["time"], "2022-02-16T17:37:47.337045569Z")
        for key in ("logs", "metrics", "resource_statuses"):
            self.assertIsNone(raw_event["puppet_report"].get(key))

    def test_cache_miss_ok(self):
        # delete from cache to ensure miss
        delete_from_cache(self.instance.pk)
        response = self.make_request(
            reverse("puppet:post_report", args=(self.instance.pk,)),
            json_data=build_report(),
            auth_header=f"Token {self.token}"
        )
        self.assertEqual(response.status_code, 200)
