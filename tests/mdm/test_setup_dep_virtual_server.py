from functools import reduce
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
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.crypto import encrypt_cms_payload
from zentral.contrib.mdm.dep import add_dep_token_certificate
from zentral.contrib.mdm.models import DEPToken, DEPVirtualServer
from .utils import force_dep_enrollment, force_dep_virtual_server


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SetupDEPVirtualServerViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

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

    def _build_mock_dep_client(self):
        server_name = get_random_string(12)
        server_uuid = uuid.uuid4()
        mock_dep_client = Mock()
        mock_dep_client.get_account.return_value = {
            "org_id": get_random_string(12),
            "org_name": "Example ORG",
            "admin_id": "admin@example.com",
            "org_email": "user@example.com",
            "org_phone": "0123456789",
            "org_address": "1 rue des Fraises\n69001 Lyon\nFrance",
            "org_type": "org",
            "org_version": "v2",
            "server_uuid": str(server_uuid),
            "server_name": server_name,
        }
        return mock_dep_client, server_name, server_uuid

    def _build_encrypted_token(self, dep_token):
        payload = (
            "-----BEGIN MESSAGE-----\n" +
            json.dumps({"consumer_key": "ckey", "consumer_secret": "csecret",
                        "access_token": "atoken", "access_secret": "asecret"}) +
            "\n-----END MESSAGE-----"
        )
        encrypted_token = BytesIO(encrypt_cms_payload(payload.encode("utf-8"), dep_token.certificate))
        encrypted_token.name = "encrypted_token"
        return encrypted_token

    # list DEP virtual servers

    def test_list_dep_virtual_servers_redirect(self):
        self._login_redirect(reverse("mdm:dep_virtual_servers"))

    def test_list_dep_virtual_servers_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:dep_virtual_servers"))
        self.assertEqual(response.status_code, 403)

    def test_list_dep_virtual_servers(self):
        virtual_server = force_dep_virtual_server()
        self._login("mdm.view_depvirtualserver")
        response = self.client.get(reverse("mdm:dep_virtual_servers"))
        self.assertTemplateUsed(response, "mdm/depvirtualserver_list.html")
        self.assertContains(response, virtual_server.name)

    # DEP virtual server

    def test_dep_virtual_server_redirect(self):
        virtual_server = force_dep_virtual_server()
        self._login_redirect(virtual_server.get_absolute_url())

    def test_dep_virtual_server_permission_denied(self):
        virtual_server = force_dep_virtual_server()
        self._login()
        response = self.client.get(virtual_server.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_dep_virtual_server_no_links(self):
        enrollment = force_dep_enrollment(self.mbu)
        virtual_server = enrollment.virtual_server
        virtual_server.default_enrollment = enrollment
        virtual_server.save()
        self._login("mdm.view_depvirtualserver")
        response = self.client.get(virtual_server.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertNotContains(response, enrollment.get_absolute_url())
        self.assertNotContains(response, reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)))
        self.assertNotContains(response, reverse("mdm:renew_dep_token", args=(virtual_server.token.pk,)))

    def test_dep_virtual_server_links(self):
        enrollment = force_dep_enrollment(self.mbu)
        virtual_server = enrollment.virtual_server
        virtual_server.default_enrollment = enrollment
        virtual_server.save()
        self._login("mdm.view_depvirtualserver", "mdm.change_depvirtualserver", "mdm.view_depenrollment")
        response = self.client.get(virtual_server.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_detail.html")
        self.assertContains(response, enrollment.name)
        self.assertContains(response, enrollment.get_absolute_url())
        self.assertContains(response, reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)))
        self.assertContains(response, reverse("mdm:renew_dep_token", args=(virtual_server.token.pk,)))

    # update DEP virtual server

    def test_update_dep_virtual_server_redirect(self):
        virtual_server = force_dep_virtual_server()
        self._login_redirect(reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)))

    def test_update_dep_virtual_server_permission_denied(self):
        virtual_server = force_dep_virtual_server()
        self._login()
        response = self.client.get(reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_dep_virtual_server_get(self):
        enrollment1 = force_dep_enrollment(self.mbu)
        virtual_server = enrollment1.virtual_server
        enrollment2 = force_dep_enrollment(self.mbu)
        self._login("mdm.change_depvirtualserver")
        response = self.client.get(reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_form.html")
        self.assertContains(response, enrollment1.name)
        self.assertNotContains(response, enrollment2.name)

    def test_update_dep_virtual_server_post(self):
        enrollment = force_dep_enrollment(self.mbu)
        virtual_server = enrollment.virtual_server
        self.assertIsNone(virtual_server.default_enrollment)
        self._login("mdm.change_depvirtualserver", "mdm.view_depvirtualserver")
        response = self.client.post(reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)),
                                    {"default_enrollment": enrollment.pk},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_detail.html")
        self.assertContains(response, enrollment.name)
        virtual_server.refresh_from_db()
        self.assertEqual(virtual_server.default_enrollment, enrollment)

    # connect DEP virtual server

    def test_connect_dep_virtual_server_redirect(self):
        self._login_redirect(reverse("mdm:connect_dep_virtual_server"))

    def test_connect_dep_virtual_server_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:connect_dep_virtual_server"))
        self.assertEqual(response.status_code, 403)

    def test_connect_dep_virtual_server_get(self):
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        response = self.client.get(reverse("mdm:connect_dep_virtual_server"))
        self.assertRedirects(response, reverse("mdm:dep_virtual_servers"))

    def test_connect_dep_virtual_server_post_start_no_session_token(self):
        self._login("mdm.add_depvirtualserver")
        self.assertNotIn("current_dep_token_id", self.client.session)
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_connect.html")
        dep_token = DEPToken.objects.get(pk=self.client.session["current_dep_token_id"])
        self.assertIsNone(dep_token.consumer_key)

    def test_connect_dep_virtual_server_post_start_valid_session_token(self):
        self._login("mdm.add_depvirtualserver")
        session = self.client.session
        dep_token = DEPToken.objects.create()
        session["current_dep_token_id"] = dep_token.pk
        session.save()
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_connect.html")
        dep_token2 = DEPToken.objects.get(pk=self.client.session["current_dep_token_id"])
        self.assertEqual(dep_token, dep_token2)

    def test_connect_dep_virtual_server_post_start_invalid_session_token(self):
        self._login("mdm.add_depvirtualserver")
        session = self.client.session
        session["current_dep_token_id"] = 3120938120398
        session.save()
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_connect.html")
        dep_token = DEPToken.objects.get(pk=self.client.session["current_dep_token_id"])
        self.assertNotEqual(dep_token.pk, 3120938120398)

    def test_connect_dep_virtual_server_post_start_attached_server_redirect(self):
        virtual_server = force_dep_virtual_server()
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        session = self.client.session
        session["current_dep_token_id"] = virtual_server.token.pk
        session.save()
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"))
        self.assertRedirects(response, virtual_server.get_absolute_url())

    def test_connect_dep_virtual_server_post_cancel(self):
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"),
                                    {"action": "cancel"})
        self.assertRedirects(response, reverse("mdm:dep_virtual_servers"))

    def test_connect_dep_virtual_server_post_no_encrypted_token_error(self):
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        session = self.client.session
        dep_token = DEPToken.objects.create()
        session["current_dep_token_id"] = dep_token.pk
        session.save()
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"),
                                    {"action": "upload"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_connect.html")
        dep_token2 = DEPToken.objects.get(pk=self.client.session["current_dep_token_id"])
        self.assertEqual(dep_token, dep_token2)
        self.assertFormError(response.context["form"], "encrypted_token", "This field is mandatory")

    def test_connect_dep_virtual_server_post_bad_encrypted_token_error(self):
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        session = self.client.session
        dep_token = DEPToken.objects.create()
        session["current_dep_token_id"] = dep_token.pk
        session.save()
        encrypted_token = BytesIO(b'yolofomo')
        encrypted_token.name = "encrypted_token"
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"),
                                    {"action": "upload",
                                     "encrypted_token": encrypted_token})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/depvirtualserver_connect.html")
        dep_token2 = DEPToken.objects.get(pk=self.client.session["current_dep_token_id"])
        self.assertEqual(dep_token, dep_token2)
        self.assertFormError(response.context["form"], "encrypted_token", "Could not read or use encrypted token")

    @patch("zentral.contrib.mdm.forms.DEPClient")
    def test_connect_dep_virtual_server_post(self, DEPClient):
        mock_dep_client, server_name, server_uuid = self._build_mock_dep_client()
        DEPClient.return_value = mock_dep_client
        self._login("mdm.add_depvirtualserver", "mdm.view_depvirtualserver")
        session = self.client.session
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        session["current_dep_token_id"] = dep_token.pk
        session.save()
        response = self.client.post(reverse("mdm:connect_dep_virtual_server"),
                                    {"action": "upload",
                                     "encrypted_token": self._build_encrypted_token(dep_token)})
        self.assertNotIn("current_dep_token_id", self.client.session)
        dep_token.refresh_from_db()
        self.assertRedirects(response, dep_token.virtual_server.get_absolute_url())
        self.assertEqual(dep_token.consumer_key, "ckey")
        self.assertEqual(dep_token.get_consumer_secret(), "csecret")
        self.assertEqual(dep_token.access_token, "atoken")
        self.assertEqual(dep_token.get_access_secret(), "asecret")
        self.assertEqual(dep_token.virtual_server.name, server_name)
        self.assertEqual(dep_token.virtual_server.uuid, server_uuid)
        self.assertEqual(dep_token.virtual_server.organization.name, "Example ORG")
        mock_dep_client.get_account.assert_called_once()

    # download DEP token public key

    def test_download_dep_token_public_key_redirect(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login_redirect(reverse("mdm:download_dep_token_public_key", args=(dep_token.pk,)))

    def test_download_dep_token_public_key_permission_denied(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login()
        response = self.client.get(reverse("mdm:download_dep_token_public_key", args=(dep_token.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_download_dep_token_public_key(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login("mdm.add_depvirtualserver")
        response = self.client.get(reverse("mdm:download_dep_token_public_key", args=(dep_token.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/x-pem-file")
        self.assertEqual(dep_token.certificate, b"".join(response.streaming_content))

    # renew DEP token

    def test_renew_dep_token_redirect(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login_redirect(reverse("mdm:renew_dep_token", args=(dep_token.pk,)))

    def test_renew_dep_token_permission_denied(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login()
        response = self.client.get(reverse("mdm:renew_dep_token", args=(dep_token.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_renew_dep_token_get(self):
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login("mdm.change_depvirtualserver")
        response = self.client.get(reverse("mdm:renew_dep_token", args=(dep_token.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/deptoken_renew.html")
        self.assertContains(response, "Renew DEP token")

    @patch("zentral.contrib.mdm.forms.DEPClient")
    def test_renew_dep_token_post_new_virtual_server(self, DEPClient):
        mock_dep_client, server_name, server_uuid = self._build_mock_dep_client()
        DEPClient.return_value = mock_dep_client
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login("mdm.change_depvirtualserver")
        dep_token.consumer_key = "oldckey"
        dep_token.set_consumer_secret("oldcsecret")
        dep_token.access_token = "oldatoken"
        dep_token.set_access_secret("oldasecret")
        dep_token.save()
        # new virtual server
        self.assertEqual(DEPVirtualServer.objects.filter(uuid=server_uuid).count(), 0)
        self._login("mdm.change_depvirtualserver", "mdm.view_depvirtualserver")
        response = self.client.post(reverse("mdm:renew_dep_token", args=(dep_token.pk,)),
                                    {"encrypted_token": self._build_encrypted_token(dep_token)})
        self.assertRedirects(response, dep_token.virtual_server.get_absolute_url())
        dep_token.refresh_from_db()
        self.assertEqual(dep_token.consumer_key, "ckey")
        self.assertEqual(dep_token.get_consumer_secret(), "csecret")
        self.assertEqual(dep_token.access_token, "atoken")
        self.assertEqual(dep_token.get_access_secret(), "asecret")
        self.assertEqual(dep_token.virtual_server.name, server_name)
        self.assertEqual(dep_token.virtual_server.uuid, server_uuid)
        self.assertEqual(dep_token.virtual_server.organization.name, "Example ORG")
        mock_dep_client.get_account.assert_called_once()

    @patch("zentral.contrib.mdm.forms.DEPClient")
    def test_renew_dep_token_post_existing_virtual_server(self, DEPClient):
        mock_dep_client, server_name, server_uuid = self._build_mock_dep_client()
        DEPClient.return_value = mock_dep_client
        dep_token = DEPToken.objects.create()
        add_dep_token_certificate(dep_token)
        self._login("mdm.change_depvirtualserver")
        dep_token.consumer_key = "oldckey"
        dep_token.set_consumer_secret("oldcsecret")
        dep_token.access_token = "oldatoken"
        dep_token.set_access_secret("oldasecret")
        dep_token.save()
        # create an existing virtual server with this new server_name, server uuid
        existing_virtual_server = force_dep_virtual_server(server_uuid)
        existing_virtual_server_token_pk = existing_virtual_server.token.pk
        self._login("mdm.change_depvirtualserver", "mdm.view_depvirtualserver")
        response = self.client.post(reverse("mdm:renew_dep_token", args=(dep_token.pk,)),
                                    {"encrypted_token": self._build_encrypted_token(dep_token)})
        self.assertRedirects(response, dep_token.virtual_server.get_absolute_url())
        dep_token.refresh_from_db()
        self.assertEqual(dep_token.consumer_key, "ckey")
        self.assertEqual(dep_token.get_consumer_secret(), "csecret")
        self.assertEqual(dep_token.access_token, "atoken")
        self.assertEqual(dep_token.get_access_secret(), "asecret")
        self.assertEqual(dep_token.virtual_server.name, server_name)
        self.assertEqual(dep_token.virtual_server.uuid, server_uuid)
        self.assertEqual(dep_token.virtual_server.organization.name, "Example ORG")
        mock_dep_client.get_account.assert_called_once()
        # old token was deleted
        self.assertEqual(DEPToken.objects.filter(pk=existing_virtual_server_token_pk).count(), 0)
        self.assertEqual(dep_token.virtual_server, existing_virtual_server)
        self.assertEqual(dep_token.virtual_server.name, server_name)
