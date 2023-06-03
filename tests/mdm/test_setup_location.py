import base64
import datetime
from functools import reduce
import hashlib
from io import BytesIO
import json
import operator
from unittest.mock import patch, Mock
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.mdm.apps_books import AppsBooksAPIError
from zentral.contrib.mdm.models import Location


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SetupLocationViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _force_location(self, server_token_hash=None, name=None):
        location = Location.objects.create(
            server_token_hash=server_token_hash or get_random_string(40, allowed_chars='abcdef0123456789'),
            server_token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            name=name or get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
        )
        location.set_server_token(get_random_string(12))
        location.save()
        server_token = location.set_notification_auth_token()
        location.save()
        return location, server_token

    def _build_vppserver_token(self, org_name=None, skip_org_name=False):
        server_token_data = {
            "expDate": "2043-12-05T16:53:11+0000",
            "server_token": "aaaa",
        }
        if org_name is None:
            org_name = get_random_string(12)
        if not skip_org_name:
            server_token_data["orgName"] = org_name
        content = base64.b64encode(json.dumps(server_token_data).encode("utf-8"))
        digest = hashlib.sha1(content).hexdigest()
        vppserver_token = BytesIO(content)
        vppserver_token.name = "test.vppserver_token"
        return vppserver_token, digest

    # rewrap secrets

    def test_rewrap_secrets(self):
        location, _ = self._force_location()
        server_token = location.get_server_token()
        self.assertIsNotNone(server_token)
        location.rewrap_secrets()
        self.assertEqual(location.get_server_token(), server_token)

    # list server server_tokens

    def test_list_locations_redirect(self):
        self._login_redirect(reverse("mdm:locations"))

    def test_list_locations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:locations"))
        self.assertEqual(response.status_code, 403)

    def test_list_locations(self):
        location, _ = self._force_location()
        self._login("mdm.view_location")
        response = self.client.get(reverse("mdm:locations"))
        self.assertTemplateUsed(response, "mdm/location_list.html")
        self.assertContains(response, location.name)

    # view server server_token

    def test_view_locations_redirect(self):
        location, _ = self._force_location()
        self._login_redirect(reverse("mdm:location", args=(location.pk,)))

    def test_view_location_permission_denied(self):
        location, _ = self._force_location()
        self._login()
        response = self.client.get(reverse("mdm:location", args=(location.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_location(self):
        location, _ = self._force_location()
        self._login("mdm.view_location")
        response = self.client.get(reverse("mdm:location", args=(location.pk,)))
        self.assertTemplateUsed(response, "mdm/location_detail.html")
        self.assertContains(response, location.name)

    # delete server server_token

    def test_delete_locations_redirect(self):
        location, _ = self._force_location()
        self._login_redirect(reverse("mdm:delete_location", args=(location.pk,)))

    def test_delete_location_permission_denied(self):
        location, _ = self._force_location()
        self._login()
        response = self.client.get(reverse("mdm:delete_location", args=(location.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_location_get(self):
        location, _ = self._force_location()
        self._login("mdm.delete_location")
        response = self.client.get(reverse("mdm:delete_location", args=(location.pk,)))
        self.assertTemplateUsed(response, "mdm/location_confirm_delete.html")

    def test_delete_location_post(self):
        location, _ = self._force_location()
        self._login("mdm.delete_location", "mdm.view_location")
        response = self.client.post(reverse("mdm:delete_location", args=(location.pk,)), follow=True)
        self.assertTemplateUsed(response, "mdm/location_list.html")
        self.assertNotContains(response, location.name)

    # create server server_token

    def test_create_location_redirect(self):
        self._login_redirect(reverse("mdm:create_location"))

    def test_create_location_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_location"))
        self.assertEqual(response.status_code, 403)

    def test_create_location_get(self):
        self._login("mdm.add_location")
        response = self.client.get(reverse("mdm:create_location"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/location_form.html")

    def test_create_location_post_bad_server_token(self):
        self._login("mdm.add_location")
        vppserver_token = BytesIO(b'yolofomo')
        vppserver_token.name = "bad.vppserver_token"
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/location_form.html")
        self.assertFormError(response, "form", "server_token_file", "Not a valid server token")

    def test_create_location_post_hash_collision(self):
        vppserver_token, server_token_hash = self._build_vppserver_token(skip_org_name=True)
        location, _ = self._force_location(server_token_hash=server_token_hash)
        self._login("mdm.add_location")
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form",
                             "server_token_file",
                             "A location with the same server token already exists.")

    def test_create_location_post_no_org_name(self):
        self._login("mdm.add_location")
        vppserver_token, _ = self._build_vppserver_token(skip_org_name=True)
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "server_token_file", "Could not get organization name.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_location_post_invalid_server_token(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.side_effect = AppsBooksAPIError("Invalid server_token")
        AppsBooksClient.return_value = client
        self._login("mdm.add_location")
        vppserver_token, _ = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "server_token_file", "Could not get client information")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_location_post_invalid_config(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {"un": "deux"}
        AppsBooksClient.return_value = client
        self._login("mdm.add_location")
        vppserver_token, _ = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, "form", "server_token_file",
            ['Missing or bad countryISO2ACode.',
             'Missing or bad uId.',
             'Missing or bad locationName.',
             'Missing or bad defaultPlatform.',
             'Missing or bad websiteURL.',
             'Missing tokenExpirationDate.']
        )

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_location_post_missing_server_token_expiration_date(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {
            'countryISO2ACode': 'DE',
            'defaultPlatform': 'enterprisestore',
            'locationName': 'zentral.example.com',
            'uId': '0000000000',
            'websiteURL': 'https://business.apple.com'
        }
        AppsBooksClient.return_value = client
        self._login("mdm.add_location")
        vppserver_token, _ = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "server_token_file", "Missing tokenExpirationDate.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_location_post_invalid_server_token_expiration_date(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {
            'countryISO2ACode': 'DE',
            'defaultPlatform': 'enterprisestore',
            'locationName': 'zentral.example.com',
            'uId': '0000000000',
            'tokenExpirationDate': 'YOLO',
            'websiteURL': 'https://business.apple.com'
        }
        AppsBooksClient.return_value = client
        self._login("mdm.add_location")
        vppserver_token, _ = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "server_token_file", "Could not parse server token expiration date.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_location_post(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {
            'countryISO2ACode': 'DE',
            'defaultPlatform': 'enterprisestore',
            'locationName': 'zentral.example.com',
            'uId': '0000000000',
            'tokenExpirationDate': '2043-11-16T12:16:43+0000',
            'websiteURL': 'https://business.apple.com'
        }
        AppsBooksClient.return_value = client
        self._login("mdm.add_location", "mdm.view_location")
        vppserver_token, server_token_hash = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:create_location"),
                                    {"server_token_file": vppserver_token}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/location_detail.html")
        self.assertContains(response, "zentral.example.com")
        location = Location.objects.get(server_token_hash=server_token_hash)
        self.assertEqual(location.name, "zentral.example.com")

    # update server server_token

    def test_update_locations_redirect(self):
        location, _ = self._force_location()
        self._login_redirect(reverse("mdm:update_location", args=(location.pk,)))

    def test_update_location_permission_denied(self):
        location, _ = self._force_location()
        self._login()
        response = self.client.get(reverse("mdm:update_location", args=(location.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_location_get(self):
        location, _ = self._force_location()
        self._login("mdm.change_location")
        response = self.client.get(reverse("mdm:update_location", args=(location.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/location_form.html")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_update_location_post(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {
            'countryISO2ACode': 'DE',
            'defaultPlatform': 'enterprisestore',
            'locationName': 'zentral.example.com',
            'uId': '0000000000',
            'tokenExpirationDate': '2043-11-16T12:16:43+0000',
            'websiteURL': 'https://business.apple.com'
        }
        AppsBooksClient.return_value = client
        location, _ = self._force_location(name="yolo")
        self.assertEqual(location.name, "yolo")
        self._login("mdm.change_location", "mdm.view_location")
        vppserver_token, server_token_hash = self._build_vppserver_token()
        response = self.client.post(reverse("mdm:update_location", args=(location.pk,)),
                                    {"server_token_file": vppserver_token}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/location_detail.html")
        location = Location.objects.get(server_token_hash=server_token_hash)
        self.assertEqual(location.name, "zentral.example.com")

    # notify

    def test_notify_location_missing_header(self):
        location, _ = self._force_location()
        response = self.client.post(reverse("mdm_public:notify_location", args=(location.mdm_info_id,)))
        self.assertEqual(response.status_code, 403)

    def test_notify_location_bad_header(self):
        location, _ = self._force_location()
        response = self.client.post(reverse("mdm_public:notify_location", args=(location.mdm_info_id,)),
                                    HTTP_AUTHORIZATION="Malformed")
        self.assertEqual(response.status_code, 403)

    def test_notify_location_unknown(self):
        location, _ = self._force_location()
        response = self.client.post(reverse("mdm_public:notify_location", args=(location.mdm_info_id,)),
                                    HTTP_AUTHORIZATION="Bearer Unknown")
        self.assertEqual(response.status_code, 403)

    def test_notify_location_bad_payload(self):
        location, server_token = self._force_location()
        response = self.client.post(reverse("mdm_public:notify_location", args=(location.mdm_info_id,)),
                                    content_type="text/xml",
                                    data="",
                                    HTTP_AUTHORIZATION=f"Bearer {server_token}")
        self.assertEqual(response.status_code, 400)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_notify_location(self, post_raw_event):

        location, server_token = self._force_location()
        response = self.client.post(reverse("mdm_public:notify_location", args=(location.mdm_info_id,)),
                                    content_type="application/json",
                                    data={"yolo": "un"},
                                    HTTP_AUTHORIZATION=f"Bearer {server_token}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(post_raw_event.call_args_list), 1)
        routing_key, raw_event = post_raw_event.call_args_list[0].args
        self.assertEqual(routing_key, "mdm_apps_books_notification")
        raw_event["metadata"].pop("created_at")
        self.assertEqual(
            raw_event,
            {'data': {'yolo': 'un'},
             'metadata': {'request': {'user_agent': '', 'ip': '127.0.0.1'}},
             'location': {'pk': location.pk, 'mdm_info_id': str(location.mdm_info_id)}}
        )
