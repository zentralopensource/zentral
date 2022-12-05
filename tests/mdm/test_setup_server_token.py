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
from zentral.contrib.mdm.models import ServerToken


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SetupServerTokenViewsTestCase(TestCase):
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

    def _force_server_token(self, token_hash=None, location_name=None):
        server_token = ServerToken(
            token_hash=token_hash or get_random_string(40, allowed_chars='abcdef0123456789'),
            token=get_random_string(12),
            token_expiration_date=datetime.date(2050, 1, 1),
            organization_name=get_random_string(12),
            country_code="DE",
            library_uid=str(uuid.uuid4()),
            location_name=location_name or get_random_string(12),
            platform="enterprisestore",
            website_url="https://business.apple.com",
            mdm_info_id=uuid.uuid4(),
            notification_auth_token_hash=get_random_string(64, allowed_chars='abcdef0123456789'),
        )
        auth_token = server_token.set_notification_auth_token()
        server_token.save()
        return server_token, auth_token

    def _build_vpptoken(self, org_name=None, skip_org_name=False):
        token_data = {
            "expDate": "2043-12-05T16:53:11+0000",
            "token": "aaaa",
        }
        if org_name is None:
            org_name = get_random_string(12)
        if not skip_org_name:
            token_data["orgName"] = org_name
        content = base64.b64encode(json.dumps(token_data).encode("utf-8"))
        digest = hashlib.sha1(content).hexdigest()
        vpptoken = BytesIO(content)
        vpptoken.name = "test.vpptoken"
        return vpptoken, digest

    # list server tokens

    def test_list_server_tokens_redirect(self):
        self._login_redirect(reverse("mdm:server_tokens"))

    def test_list_server_tokens_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:server_tokens"))
        self.assertEqual(response.status_code, 403)

    def test_list_server_tokens(self):
        server_token, _ = self._force_server_token()
        self._login("mdm.view_servertoken")
        response = self.client.get(reverse("mdm:server_tokens"))
        self.assertTemplateUsed(response, "mdm/servertoken_list.html")
        self.assertContains(response, server_token.location_name)

    # view server token

    def test_view_server_tokens_redirect(self):
        server_token, _ = self._force_server_token()
        self._login_redirect(reverse("mdm:server_token", args=(server_token.pk,)))

    def test_view_server_token_permission_denied(self):
        server_token, _ = self._force_server_token()
        self._login()
        response = self.client.get(reverse("mdm:server_token", args=(server_token.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_server_token(self):
        server_token, _ = self._force_server_token()
        self._login("mdm.view_servertoken")
        response = self.client.get(reverse("mdm:server_token", args=(server_token.pk,)))
        self.assertTemplateUsed(response, "mdm/servertoken_detail.html")
        self.assertContains(response, server_token.location_name)

    # delete server token

    def test_delete_server_tokens_redirect(self):
        server_token, _ = self._force_server_token()
        self._login_redirect(reverse("mdm:delete_server_token", args=(server_token.pk,)))

    def test_delete_server_token_permission_denied(self):
        server_token, _ = self._force_server_token()
        self._login()
        response = self.client.get(reverse("mdm:delete_server_token", args=(server_token.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_server_token_get(self):
        server_token, _ = self._force_server_token()
        self._login("mdm.delete_servertoken")
        response = self.client.get(reverse("mdm:delete_server_token", args=(server_token.pk,)))
        self.assertTemplateUsed(response, "mdm/servertoken_confirm_delete.html")

    def test_delete_server_token_post(self):
        server_token, _ = self._force_server_token()
        self._login("mdm.delete_servertoken", "mdm.view_servertoken")
        response = self.client.post(reverse("mdm:delete_server_token", args=(server_token.pk,)), follow=True)
        self.assertTemplateUsed(response, "mdm/servertoken_list.html")
        self.assertNotContains(response, server_token.location_name)

    # create server token

    def test_create_server_token_redirect(self):
        self._login_redirect(reverse("mdm:create_server_token"))

    def test_create_server_token_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_server_token"))
        self.assertEqual(response.status_code, 403)

    def test_create_server_token_get(self):
        self._login("mdm.add_servertoken")
        response = self.client.get(reverse("mdm:create_server_token"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/servertoken_form.html")

    def test_create_server_token_post_bad_token(self):
        self._login("mdm.add_servertoken")
        vpptoken = BytesIO(b'yolofomo')
        vpptoken.name = "bad.vpptoken"
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/servertoken_form.html")
        self.assertFormError(response, "form", "token_file", "Not a valid token")

    def test_create_server_token_post_hash_collision(self):
        vpptoken, token_hash = self._build_vpptoken(skip_org_name=True)
        server_token, _ = self._force_server_token(token_hash=token_hash)
        self._login("mdm.add_servertoken")
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "token_file", "A server token with the same token already exists.")

    def test_create_server_token_post_no_org_name(self):
        self._login("mdm.add_servertoken")
        vpptoken, _ = self._build_vpptoken(skip_org_name=True)
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "token_file", "Could not get organization name.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_server_token_post_invalid_token(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.side_effect = AppsBooksAPIError("Invalid token")
        AppsBooksClient.return_value = client
        self._login("mdm.add_servertoken")
        vpptoken, _ = self._build_vpptoken()
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "token_file", "Could not get client information")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_server_token_post_invalid_config(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {"un": "deux"}
        AppsBooksClient.return_value = client
        self._login("mdm.add_servertoken")
        vpptoken, _ = self._build_vpptoken()
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(
            response, "form", "token_file",
            ['Missing or bad countryISO2ACode.',
             'Missing or bad uId.',
             'Missing or bad locationName.',
             'Missing or bad defaultPlatform.',
             'Missing or bad websiteURL.',
             'Missing tokenExpirationDate.']
        )

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_server_token_post_missing_token_expiration_date(self, AppsBooksClient):
        client = Mock()
        client.get_client_config.return_value = {
            'countryISO2ACode': 'DE',
            'defaultPlatform': 'enterprisestore',
            'locationName': 'zentral.example.com',
            'uId': '0000000000',
            'websiteURL': 'https://business.apple.com'
        }
        AppsBooksClient.return_value = client
        self._login("mdm.add_servertoken")
        vpptoken, _ = self._build_vpptoken()
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "token_file", "Missing tokenExpirationDate.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_server_token_post_invalid_token_expiration_date(self, AppsBooksClient):
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
        self._login("mdm.add_servertoken")
        vpptoken, _ = self._build_vpptoken()
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response, "form", "token_file", "Could not parse token expiration date.")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_create_server_token_post(self, AppsBooksClient):
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
        self._login("mdm.add_servertoken", "mdm.view_servertoken")
        vpptoken, token_hash = self._build_vpptoken()
        response = self.client.post(reverse("mdm:create_server_token"),
                                    {"token_file": vpptoken}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/servertoken_detail.html")
        self.assertContains(response, "zentral.example.com")
        server_token = ServerToken.objects.get(token_hash=token_hash)
        self.assertEqual(server_token.location_name, "zentral.example.com")

    # update server token

    def test_update_server_tokens_redirect(self):
        server_token, _ = self._force_server_token()
        self._login_redirect(reverse("mdm:update_server_token", args=(server_token.pk,)))

    def test_update_server_token_permission_denied(self):
        server_token, _ = self._force_server_token()
        self._login()
        response = self.client.get(reverse("mdm:update_server_token", args=(server_token.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_server_token_get(self):
        server_token, _ = self._force_server_token()
        self._login("mdm.change_servertoken")
        response = self.client.get(reverse("mdm:update_server_token", args=(server_token.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/servertoken_form.html")

    @patch("zentral.contrib.mdm.forms.AppsBooksClient")
    def test_update_server_token_post(self, AppsBooksClient):
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
        server_token, _ = self._force_server_token(location_name="yolo")
        self.assertEqual(server_token.location_name, "yolo")
        self._login("mdm.change_servertoken", "mdm.view_servertoken")
        vpptoken, token_hash = self._build_vpptoken()
        response = self.client.post(reverse("mdm:update_server_token", args=(server_token.pk,)),
                                    {"token_file": vpptoken}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/servertoken_detail.html")
        server_token = ServerToken.objects.get(token_hash=token_hash)
        self.assertEqual(server_token.location_name, "zentral.example.com")

    # notify

    def test_notify_server_token_missing_header(self):
        server_token, _ = self._force_server_token()
        response = self.client.post(reverse("mdm:notify_server_token", args=(server_token.mdm_info_id,)))
        self.assertEqual(response.status_code, 403)

    def test_notify_server_token_bad_header(self):
        server_token, _ = self._force_server_token()
        response = self.client.post(reverse("mdm:notify_server_token", args=(server_token.mdm_info_id,)),
                                    HTTP_AUTHORIZATION="Malformed")
        self.assertEqual(response.status_code, 403)

    def test_notify_server_token_unknown(self):
        server_token, _ = self._force_server_token()
        response = self.client.post(reverse("mdm:notify_server_token", args=(server_token.mdm_info_id,)),
                                    HTTP_AUTHORIZATION="Bearer Unknown")
        self.assertEqual(response.status_code, 403)

    def test_notify_server_token_bad_payload(self):
        server_token, auth_token = self._force_server_token()
        response = self.client.post(reverse("mdm:notify_server_token", args=(server_token.mdm_info_id,)),
                                    content_type="text/xml",
                                    data="",
                                    HTTP_AUTHORIZATION=f"Bearer {auth_token}")
        self.assertEqual(response.status_code, 400)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_raw_event")
    def test_notify_server_token(self, post_raw_event):

        server_token, auth_token = self._force_server_token()
        response = self.client.post(reverse("mdm:notify_server_token", args=(server_token.mdm_info_id,)),
                                    content_type="application/json",
                                    data={"yolo": "un"},
                                    HTTP_AUTHORIZATION=f"Bearer {auth_token}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(post_raw_event.call_args_list), 1)
        routing_key, raw_event = post_raw_event.call_args_list[0].args
        self.assertEqual(routing_key, "mdm_apps_books_notification")
        raw_event["metadata"].pop("created_at")
        self.assertEqual(
            raw_event,
            {'data': {'yolo': 'un'},
             'metadata': {'request': {'user_agent': '', 'ip': '127.0.0.1'}},
             'server_token': {'pk': server_token.pk, 'mdm_info_id': str(server_token.mdm_info_id)}}
        )
