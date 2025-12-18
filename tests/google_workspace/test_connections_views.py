from functools import reduce
import operator
import uuid
import json
from unittest.mock import patch, Mock
from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping
from django.core.files.uploadedfile import SimpleUploadedFile
from oauthlib.oauth2.rfc6749.errors import InvalidGrantError
from zentral.contrib.inventory.models import Tag
from django.core.cache import cache
from zentral.contrib.google_workspace.api_client import _AdminSDKClient
from googleapiclient.errors import HttpError
from zentral.core.events.base import AuditEvent


class ConnectionViewsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utils

    def _login_redirect(self, url_name, *args):
        url = reverse(f"google_workspace:{url_name}", args=args)
        response = self.client.get(url)
        self.assertRedirects(response, f"{reverse('login')}?next={url}")

    def _permission_denied(self, url_name, *args):
        url = reverse(f"google_workspace:{url_name}", args=args)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

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

    def _given_connection(
            self,
            user_info: str = json.dumps({
                "refresh_token": get_random_string(12),
                "client_id": get_random_string(12),
                "client_secret": get_random_string(12)
            }),
            type: Connection.Type = Connection.Type.OAUTH_ADMIN_SDK,
            customer_id: str = None):
        name = get_random_string(12)
        
        connection = Connection.objects.create(name=name, type=type)

        match type:
            case Connection.Type.OAUTH_ADMIN_SDK:
                client_config = json.dumps({"web": {}})
                connection.set_client_config(client_config)
                if user_info:
                    connection.set_user_info(user_info)
            case Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY:
                connection.customer_id = customer_id

        connection.save()

        return connection

    def _given_tag(self):
        return Tag.objects.create(
            name=f"tag_{get_random_string(5)}"
        )

    def _given_group_tag_mapping(self, connection, tag=None):
        group_tag_mapping = GroupTagMapping.objects.create(
            group_email=f"{connection.name}@zentral.com",
            connection=connection)
        if tag:
            group_tag_mapping.tags.set([tag])

        return group_tag_mapping

    def _given_client_config(self, token_uri="https://oauth2.zentral.com/token"):
        content = f"""{{
            "web":{{
                "client_id":"{get_random_string(25)}",
                "auth_uri":"https://zentral.com/oauth2/auth",
                "token_uri":"{token_uri}",
                "redirect_uris":["https://zentral.com/google_workspace/connections/redirect/"]
            }}
        }}"""
        return SimpleUploadedFile(
            "config.json",
            content.encode("utf-8")
        )

    def _assert_audit_event_send(self, connection: Connection, post_event, callbacks,
                                 action: AuditEvent.Action, prev_value: dict[str, str] = None):
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]

        expected_payload = {'action': action.value,
                            'object': {
                                'model': 'google_workspace.connection',
                                'pk': str(connection.id)}}
        match action:
            case AuditEvent.Action.CREATED:
                expected_payload["object"].update({'new_value': connection.serialize_for_event()})
            case AuditEvent.Action.UPDATED:
                expected_payload["object"].update({'prev_value': prev_value})
                expected_payload["object"].update({'new_value': connection.serialize_for_event()})
            case AuditEvent.Action.DELETED:
                expected_payload["object"].update({'prev_value': prev_value})

        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"google_workspace_connection": [str(connection.id)]})
        self.assertEqual(sorted(metadata["tags"]), ["google_workspace", "zentral"])

    # IndexView

    def test_index_login_redirect(self):
        self._login_redirect("index")

    def test_index_permission_denied(self):
        self._login()
        self._permission_denied("index")

    def test_index(self):
        self._login("google_workspace.view_connection")

        response = self.client.get(reverse("google_workspace:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Google Workspace")

    def test_index_post(self):
        self._login("google_workspace.view_connection")

        response = self.client.post(reverse("google_workspace:index"), follow=True)
        self.assertEqual(response.status_code, 405)

    # ConnectionsView

    def test_connection_list_login_redirect(self):
        self._login_redirect("connections")

    def test_connection_list_permission_denied(self):
        self._login()
        self._permission_denied("connections")

    def test_connection_list(self):
        self._login("google_workspace.view_connection")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:connections"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_list.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)

        self.assertNotContains(response, "Create connection")
        self.assertNotContains(response, "Edit connection")
        self.assertNotContains(response, "Delete connection")

    def test_connection_list_with_edit_permissions(self):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_connection",
                    "google_workspace.change_connection")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:connections"))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_list.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)

        self.assertContains(response, "Create connection")
        self.assertContains(response, "Edit connection")
        self.assertNotContains(response, "Delete connection")

    def test_connection_list_with_delete_permissions(self):
        self._login("google_workspace.view_connection",
                    "google_workspace.delete_connection")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:connections"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_list.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)

        self.assertNotContains(response, "Create connection")
        self.assertNotContains(response, "Edit connection")
        self.assertContains(response, "Delete connection")

    def test_connection_list_with_delete_permissions_can_not_delete(self):
        self._login("google_workspace.view_connection",
                    "google_workspace.delete_connection")
        connection = self._given_connection()
        self._given_group_tag_mapping(connection)

        response = self.client.get(reverse("google_workspace:connections"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_list.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)

        self.assertNotContains(response, "Create connection")
        self.assertNotContains(response, "Edit connection")
        self.assertNotContains(response, "Delete connection")

    # CreateConnectionView

    def test_connection_create_login_redirect(self):
        self._login_redirect("create_connection")

    def test_connection_create_permission_denied(self):
        self._login()
        self._permission_denied("create_connection")

    def test_connection_create(self):
        self._login("google_workspace.add_connection")

        response = self.client.get(reverse("google_workspace:create_connection"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertContains(response, "Create connection")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_connection_create_redirect(self, post_event):
        self._login("google_workspace.add_connection")
        connection_name = get_random_string(12)
        client_config = self._given_client_config()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("google_workspace:create_connection"),
                                        {
                                            "name": connection_name,
                                            "serialized_client_config": client_config,
                                            "type": Connection.Type.OAUTH_ADMIN_SDK
                                        })

        connection = Connection.objects.get(name=connection_name)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].startswith("https://zentral.com/oauth2/auth"))
        self._assert_audit_event_send(connection, post_event, callbacks, AuditEvent.Action.CREATED)

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_connection_create_redirect_cloud_id(self, post_event, build):
        self._login("google_workspace.add_connection")
        connection_name = get_random_string(12)
        customer_id = f"C{get_random_string(5)}"
        build.return_value.groups.side_effect = HttpError(Mock(status=404), b"")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("google_workspace:create_connection"),
                                        {
                                            "name": connection_name,
                                            "customer_id": customer_id,
                                            "type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
                                        })

        connection = Connection.objects.get(name=connection_name)
        self.assertEqual(response.status_code, 302)
        self.maxDiff = None
        self._assert_audit_event_send(connection, post_event, callbacks, AuditEvent.Action.CREATED)

    def test_connection_create_form_errors(self):
        self._login("google_workspace.add_connection")

        response = self.client.post(reverse("google_workspace:create_connection"),
                                    {"type": Connection.Type.OAUTH_ADMIN_SDK},
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "name", "This field is required.")
        self.assertFormError(
            response.context["form"],
            "serialized_client_config",
            "Required for OAuth Admin SDK connection."
        )

    def test_connection_create_form_errors_cloud_id(self):
        self._login("google_workspace.add_connection")

        response = self.client.post(reverse("google_workspace:create_connection"),
                                    {"type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY},
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "name", "This field is required.")
        self.assertFormError(
            response.context["form"],
            "customer_id",
            "Required for Service Account Could Identity connection."
        )

    def test_connection_create_form_errors_cloud_id_customer_id(self):
        self._login("google_workspace.add_connection")

        response = self.client.post(reverse("google_workspace:create_connection"),
                                    {
                                        "name": get_random_string(12),
                                        "customer_id": f"B{get_random_string(5)}",
                                        "type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
                                    },
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "customer_id", "Invalid customer id.")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_create_form_errors_cloud_id_not_healthy(self, build):
        self._login("google_workspace.add_connection")
        build.return_value.groups.side_effect = HttpError(Mock(status=400), b"")

        response = self.client.post(reverse("google_workspace:create_connection"),
                                    {
                                        "name": get_random_string(12),
                                        "customer_id": f"C{get_random_string(5)}",
                                        "type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
                                    },
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "customer_id", "Customer ID is not supported.")

    # ConnectionRedirectView

    def test_connection_redirect_login_redirect(self):
        self._login_redirect("redirect")

    def test_connection_redirect_permission_denied(self):
        self._login()
        self._permission_denied("redirect")

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch('zentral.contrib.google_workspace.api_client.InstalledAppFlow.from_client_config')
    def test_connection_redirect(self, from_client_config, build):
        self._login("google_workspace.add_connection",
                    "google_workspace.view_connection")
        state = get_random_string(5)
        cache_key = f"{_AdminSDKClient.oauth2_state_cache_key_prefix}{state}"
        connection = self._given_connection()
        group_email = f"{connection.name}@zentral.com"
        cache.set(cache_key, str(connection.pk), 3600)

        from_client_config.return_value.fetch_token.return_value = None
        from_client_config.return_value.credentials.to_json.return_value = connection.get_user_info()
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]}

        response = self.client.get(reverse("google_workspace:redirect"), {"state": state, "code": "code"})

        self.assertRedirects(response, reverse("google_workspace:connection", args={connection.pk, }))

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch('zentral.contrib.google_workspace.api_client.InstalledAppFlow.from_client_config')
    def test_connection_redirect_failed_authorization(self, from_client_config, build):
        self._login("google_workspace.add_connection",
                    "google_workspace.view_connection")
        state = get_random_string(5)
        cache_key = f"{_AdminSDKClient.oauth2_state_cache_key_prefix}{state}"
        connection = self._given_connection(user_info=None)
        group_email = f"{connection.name}@zentral.com"
        cache.set(cache_key, str(connection.pk), 3600)

        from_client_config.side_effect = InvalidGrantError()
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]}

        response = self.client.get(reverse("google_workspace:redirect"), {"state": state, "code": "code"})

        self.assertRedirects(response, reverse("google_workspace:connection", args={connection.pk, }))

    def test_connection_redirect_post(self):
        self._login("google_workspace.add_connection")

        response = self.client.post(reverse("google_workspace:redirect"), follow=True)
        self.assertEqual(response.status_code, 405)

    # AuthorizeConnectionView

    def test_connection_authorize_login_redirect(self):
        self._login_redirect("authorize_connection", uuid.uuid4())

    def test_connection_authorize_permission_denied(self):
        self._login()
        self._permission_denied("authorize_connection", uuid.uuid4())

    @patch("google_auth_oauthlib.flow.InstalledAppFlow.from_client_config")
    def test_connection_authorize(self, from_client_config):
        self._login("google_workspace.view_connection")
        connection = self._given_connection(user_info=None)
        redirect_url = f"https://redirect.{get_random_string(5)}.zentral.com"
        from_client_config.return_value.authorization_url.return_value = {0: redirect_url}

        response = self.client.get(reverse("google_workspace:authorize_connection", args=(connection.pk,)))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], redirect_url)

    def test_connection_authorize_post(self):
        self._login("google_workspace.view_connection")
        connection = self._given_connection()

        response = self.client.post(reverse("google_workspace:authorize_connection", args=(connection.pk,)),
                                    follow=True)
        self.assertEqual(response.status_code, 405)

    # UpdateConnectionView

    def test_connection_udpate_login_redirect(self):
        self._login_redirect("update_connection", uuid.uuid4())

    def test_connection_udpate_permission_denied(self):
        self._login()
        self._permission_denied("update_connection", uuid.uuid4())

    def test_connection_udpate(self):
        self._login("google_workspace.change_connection")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:update_connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertContains(response, f"Update {connection.name}")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_udpate_redirect(self, build, post_event):
        self._login("google_workspace.change_connection",
                    "google_workspace.view_connection")
        connection_name = get_random_string(12)
        connection = self._given_connection()
        prev_value = connection.serialize_for_event()

        build.return_value.groups.side_effect = Exception()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("google_workspace:update_connection", args=(connection.pk,)),
                {
                    "name": connection_name,
                    "type": Connection.Type.OAUTH_ADMIN_SDK
                },
                follow=True
            )
        self.assertRedirects(response, reverse("google_workspace:connection", args={connection.pk}))
        self.assertContains(response, connection_name)
        connection.refresh_from_db()
        self._assert_audit_event_send(connection, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_udpate_redirect_cloud_id(self, build, post_event):
        self._login("google_workspace.change_connection",
                    "google_workspace.view_connection")
        connection_name = get_random_string(12)
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        prev_value = connection.serialize_for_event()
        build.return_value.groups.side_effect = HttpError(Mock(status=404), b"")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("google_workspace:update_connection", args=(connection.pk,)),
                {
                    "name": connection_name,
                    "customer_id": connection.customer_id,
                    "type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
                },
                follow=True
            )
        self.assertRedirects(response, reverse("google_workspace:connection", args={connection.pk}))
        self.assertContains(response, connection_name)
        connection.refresh_from_db()
        self._assert_audit_event_send(connection, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    def test_connection_udpate_authenticate(self):
        self._login("google_workspace.change_connection",
                    "google_workspace.view_connection")
        connection = self._given_connection(user_info=None)
        client_config = self._given_client_config()

        response = self.client.post(reverse("google_workspace:update_connection", args=(connection.pk,)),
                                    {
                                        "name": connection.name,
                                        "serialized_client_config": client_config,
                                        "type": Connection.Type.OAUTH_ADMIN_SDK
                                    })
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].startswith("https://zentral.com/oauth2/auth"))

    def test_connection_udpate_form_errors(self):
        self._login("google_workspace.change_connection",
                    "google_workspace.view_connection")
        connection = self._given_connection()
        client_config = SimpleUploadedFile(
            "config.json",
            """{"web":{}}""".encode("utf-8")
        )

        response = self.client.post(reverse("google_workspace:update_connection", args=(connection.pk,)),
                                    {
                                        "serialized_client_config": client_config,
                                        "type": Connection.Type.OAUTH_ADMIN_SDK
                                    },
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "name", "This field is required.")
        self.assertFormError(response.context["form"], "serialized_client_config", "Invalid client config.")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_udpate_form_errors_cloud_id(self, build):
        self._login("google_workspace.change_connection",
                    "google_workspace.view_connection")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}"
        )
        build.return_value.groups.side_effect = Exception()

        response = self.client.post(reverse("google_workspace:update_connection", args=(connection.pk,)),
                                    {
                                        "customer_id": f"B{get_random_string(5)}",
                                        "type": Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
                                    },
                                    follow=True)
        self.assertTemplateUsed(response, "google_workspace/connection_form.html")
        self.assertFormError(response.context["form"], "name", "This field is required.")
        self.assertFormError(response.context["form"], "customer_id", "Invalid customer id.")

    # DeleteConnectionView

    def test_connection_delete_login_redirect(self):
        self._login_redirect("delete_connection", uuid.uuid4())

    def test_connection_delete_permission_denied(self):
        self._login()
        self._permission_denied("delete_connection", uuid.uuid4())

    def test_connection_delete(self):
        self._login("google_workspace.delete_connection")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:delete_connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_confirm_delete.html")
        self.assertContains(response, "Remove connection")
        self.assertContains(response, connection.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_connection_delete_redirect(self, post_event):
        self._login("google_workspace.view_connection",
                    "google_workspace.delete_connection")
        connection = self._given_connection()
        prev_value = connection.serialize_for_event()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("google_workspace:delete_connection", args=(connection.pk,)),
                follow=True
            )

        self.assertRedirects(response, reverse("google_workspace:connections"))
        self.assertNotContains(response, connection.name)

        self._assert_audit_event_send(connection, post_event, callbacks, AuditEvent.Action.DELETED, prev_value)

    # ConnectionView

    def test_connection__redirect(self):
        self._login_redirect("connection", uuid.uuid4())

    def test_connection_permission_denied(self):
        self._login()
        self._permission_denied("connection", uuid.uuid4())

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection(self, build):
        self._login("google_workspace.view_connection")
        connection = self._given_connection()
        build.return_value = Mock()

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)
        self.assertContains(response, "Type")
        self.assertContains(response, connection.type.label)
        self.assertContains(response, "Scope")

        self.assertContains(response, "Group tag mappings (0)")

        self.assertNotContains(response, "Create new group tag mapping")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_cloud_id(self, build):
        self._login("google_workspace.view_connection")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        build.return_value = Mock()

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)
        self.assertContains(response, "Type")
        self.assertContains(response, connection.type.label)
        self.assertContains(response, "Customer ID")
        self.assertContains(response, connection.customer_id)

        self.assertContains(response, "Group tag mappings (0)")

        self.assertNotContains(response, "Create new group tag mapping")

    def test_connection_post(self):
        self._login("google_workspace.view_connection")
        connection = self._given_connection()

        response = self.client.post(reverse("google_workspace:connection", args=(connection.pk,)), follow=True)
        self.assertEqual(response.status_code, 405)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_group_tag_mapping(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value.groups.return_value.list.return_value.execute.side_effect = HttpError(Mock(status=404), b"")

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)
        self.assertContains(response, "Scope")

        self.assertContains(response, "Group tag mapping (1)")
        self.assertContains(response, group_tag_mapping.group_email)

        self.assertContains(response, "Create new group tag mapping")
        self.assertNotContains(response, "Edit new group tag mapping")
        self.assertNotContains(response, "Delete group tag mapping")

    def test_connection_group_tag_mapping_missing_refresh_token(self):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping",
                    "google_workspace.change_grouptagmapping",
                    "google_workspace.delete_grouptagmapping")
        connection = self._given_connection(f"""{{
                            "client_id": "{get_random_string(12)}",
                            "client_secret": "{get_random_string(12)}"
                        }}""")
        group_tag_mapping = self._given_group_tag_mapping(connection)

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)

        self.assertContains(response, "Group tag mapping (1)")
        self.assertContains(response, group_tag_mapping.group_email)

        self.assertNotContains(response, "Create new group tag mapping")
        self.assertNotContains(response, "Edit new group tag mapping")
        self.assertNotContains(response, "Delete group tag mapping")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_group_tag_mapping_with_edit_permision(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping",
                    "google_workspace.change_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value = Mock()

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)
        self.assertContains(response, "Scope")

        self.assertContains(response, "Group tag mapping (1)")
        self.assertContains(response, group_tag_mapping.group_email)

        self.assertContains(response, "Create new group tag mapping")
        self.assertContains(response, "Edit group tag mapping")
        self.assertNotContains(response, "Delete group tag mapping")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_group_tag_mapping_with_delete_permision(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping",
                    "google_workspace.delete_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value = Mock()

        response = self.client.get(reverse("google_workspace:connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
        self.assertContains(response, "Connection")
        self.assertContains(response, connection.name)
        self.assertContains(response, "Scope")

        self.assertContains(response, "Group tag mapping (1)")
        self.assertContains(response, group_tag_mapping.group_email)

        self.assertContains(response, "Create new group tag mapping")
        self.assertNotContains(response, "Edit group tag mapping")
        self.assertContains(response, "Delete group tag mapping")

    # CreateGroupTagMappingView

    def test_group_tag_mapping_create_login_redirect(self):
        self._login_redirect("create_group_tag_mapping", uuid.uuid4())

    def test_group_tag_mapping_create_permission_denied(self):
        self._login()
        self._permission_denied("create_group_tag_mapping", uuid.uuid4())

    def test_group_tag_mapping_create(self):
        self._login("google_workspace.add_grouptagmapping")
        connection = self._given_connection()

        response = self.client.get(reverse("google_workspace:create_group_tag_mapping", args=(connection.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertContains(response, "Add group tag mapping")
        self.assertContains(response, connection.name)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_create_redirect(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        tag = self._given_tag()
        group_email = f"{connection.name}@zentral.com"
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]
        }

        response = self.client.post(
            reverse("google_workspace:create_group_tag_mapping", args=(connection.pk, )),
            {"group_email": group_email, "tags": tag.pk},
            follow=True
        )

        group_tag_mapping = GroupTagMapping.objects.filter(group_email=group_email)
        self.assertTrue(group_tag_mapping.exists())
        group_tag_mapping = group_tag_mapping.get()
        self.assertRedirects(
            response,
            f'{reverse("google_workspace:connection", args=(connection.pk, ))}#gtm-{group_tag_mapping.pk}'
        )
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_create_redirect_cloud_id(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.add_grouptagmapping")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        tag = self._given_tag()
        group_email = f"{connection.name}@zentral.com"
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"groupKey": {"id": group_email}}]
        }

        response = self.client.post(
            reverse("google_workspace:create_group_tag_mapping", args=(connection.pk, )),
            {"group_email": group_email, "tags": tag.pk},
            follow=True
        )

        group_tag_mapping = GroupTagMapping.objects.filter(group_email=group_email)
        self.assertTrue(group_tag_mapping.exists())
        group_tag_mapping = group_tag_mapping.get()
        self.assertRedirects(
            response,
            f'{reverse("google_workspace:connection", args=(connection.pk, ))}#gtm-{group_tag_mapping.pk}'
        )
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_create_form_errors(self, build):
        self._login("google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": []
        }

        response = self.client.post(
            reverse("google_workspace:create_group_tag_mapping", args=(connection.pk,)),
            {"group_email": group_tag_mapping.group_email},
            follow=True)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertFormError(response.context["form"], "group_email", "A mapping for this group already exists.")
        self.assertFormError(response.context["form"], "tags", "This field is required.")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_create_form_errors_cloud_id(self, build):
        self._login("google_workspace.add_grouptagmapping")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": []
        }

        response = self.client.post(
            reverse("google_workspace:create_group_tag_mapping", args=(connection.pk,)),
            {"group_email": group_tag_mapping.group_email},
            follow=True)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertFormError(response.context["form"], "group_email", "A mapping for this group already exists.")
        self.assertFormError(response.context["form"], "tags", "This field is required.")

    # UpdateGroupTagMappingView

    def test_group_tag_mapping_update_login_redirect(self):
        self._login_redirect("update_group_tag_mapping", uuid.uuid4(), uuid.uuid4())

    def test_group_tag_mapping_update_permission_denied(self):
        self._login()
        self._permission_denied("update_group_tag_mapping", uuid.uuid4(), uuid.uuid4())

    def test_group_tag_mapping_update(self):
        self._login("google_workspace.change_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)

        response = self.client.get(reverse("google_workspace:update_group_tag_mapping",
                                           args=(connection.pk, group_tag_mapping.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertContains(response, "Update group tag mapping")
        self.assertContains(response, connection.name)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_update_redirect(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.change_grouptagmapping")
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_tag_mapping.group_email}]
        }

        response = self.client.post(
            reverse("google_workspace:update_group_tag_mapping", args=(connection.pk, group_tag_mapping.pk)),
            {"group_email": group_tag_mapping.group_email, "tags": group_tag_mapping.tags.first().pk},
            follow=True
        )
        self.assertRedirects(
            response,
            f'{reverse("google_workspace:connection", args=(connection.pk, ))}#gtm-{group_tag_mapping.pk}'
        )
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_update_redirect_cloud_id(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.change_grouptagmapping")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"groupKey": {"id": group_tag_mapping.group_email}}]
        }

        response = self.client.post(
            reverse("google_workspace:update_group_tag_mapping", args=(connection.pk, group_tag_mapping.pk)),
            {"group_email": group_tag_mapping.group_email, "tags": group_tag_mapping.tags.first().pk},
            follow=True
        )
        self.assertRedirects(
            response,
            f'{reverse("google_workspace:connection", args=(connection.pk, ))}#gtm-{group_tag_mapping.pk}'
        )
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_update_form_errors(self, build):
        self._login("google_workspace.change_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value.groups.return_value.get.side_effect = HttpError(Mock(status=404), b"")

        response = self.client.post(
            reverse("google_workspace:update_group_tag_mapping", args=(connection.pk, group_tag_mapping.pk)),
            {"group_email": group_tag_mapping.group_email},
            follow=True)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertFormError(response.context["form"], "group_email", "Group email not found for this connection.")
        self.assertFormError(response.context["form"], "tags", "This field is required.")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_update_form_errors_cloud_id(self, build):
        self._login("google_workspace.change_grouptagmapping")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        group_tag_mapping = self._given_group_tag_mapping(connection)
        build.return_value.groups.return_value.lookup.side_effect = HttpError(Mock(status=404), b"")

        response = self.client.post(
            reverse("google_workspace:update_group_tag_mapping", args=(connection.pk, group_tag_mapping.pk)),
            {"group_email": group_tag_mapping.group_email},
            follow=True
        )
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_form.html")
        self.assertFormError(response.context["form"], "group_email", "Group email not found for this connection.")
        self.assertFormError(response.context["form"], "tags", "This field is required.")

    # DeleteGroupTagMappingView

    def test_group_tag_mapping_delete_login_redirect(self):
        self._login_redirect("delete_group_tag_mapping", uuid.uuid4(), uuid.uuid4())

    def test_group_tag_mapping_delete_permission_denied(self):
        self._login()
        self._permission_denied("delete_group_tag_mapping", uuid.uuid4(), uuid.uuid4())

    def test_group_tag_mapping_delete(self):
        self._login("google_workspace.delete_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)

        response = self.client.get(reverse("google_workspace:delete_group_tag_mapping",
                                           args=(connection.pk, group_tag_mapping.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "google_workspace/grouptagmapping_confirm_delete.html")
        self.assertContains(response, "Remove group tag mapping")
        self.assertContains(response, group_tag_mapping.group_email)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_delete_redirect(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.delete_grouptagmapping")
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)

        build.return_value.groups.return_value.list.side_effect = HttpError(Mock(status=404), b"")

        response = self.client.post(reverse("google_workspace:delete_group_tag_mapping",
                                            args=(connection.pk, group_tag_mapping.pk)), follow=True)

        self.assertRedirects(response, reverse("google_workspace:connection", args=(connection.pk, )))
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_group_tag_mapping_delete_redirect_cloud_id(self, build):
        self._login("google_workspace.view_connection",
                    "google_workspace.delete_grouptagmapping")
        connection = self._given_connection(
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY,
            customer_id=f"C{get_random_string(5)}",
        )
        group_tag_mapping = self._given_group_tag_mapping(connection)

        build.return_value.groups.return_value.list.side_effect = HttpError(Mock(status=404), b"")

        response = self.client.post(reverse("google_workspace:delete_group_tag_mapping",
                                            args=(connection.pk, group_tag_mapping.pk)), follow=True)

        self.assertRedirects(response, reverse("google_workspace:connection", args=(connection.pk, )))
        self.assertTemplateUsed(response, "google_workspace/connection_detail.html")
