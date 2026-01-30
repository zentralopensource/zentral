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
from googleapiclient.errors import HttpError
from accounts.models import User, APIToken
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping
from zentral.contrib.inventory.models import Tag
from zentral.core.events.base import AuditEvent


class ApiViewsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        # user
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])

        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)

    # utils
    def set_permissions(self, *permissions):
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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _make_request(self, method, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return method(url, **kwargs)

    def delete(self, *args, **kwargs):
        return self._make_request(self.client.delete, *args, **kwargs)

    def post(self, url, data=None, include_token=True, *args, **kwargs):
        return self._make_request(self.client.post, url, data, include_token=include_token, *args, **kwargs)

    def put(self, *args, **kwargs):
        return self._make_request(self.client.put, *args, **kwargs)

    def get(self, *args, **kwargs):
        return self._make_request(self.client.get, *args, **kwargs)

    def _given_email(self):
        return f"{get_random_string(12)}@zentral.com"

    def _given_connection(self, user_info=json.dumps({
                "refresh_token": get_random_string(12),
                "client_id": get_random_string(12),
                "client_secret": get_random_string(12)
            })):
        name = get_random_string(12)
        client_config = json.dumps({"web": {}})
        connection = Connection.objects.create(name=name)
        connection.set_client_config(client_config)
        if user_info:
            connection.set_user_info(user_info)
        connection.save()

        return connection

    def _given_tag(self):
        return Tag.objects.create(
            name=f"tag_{get_random_string(5)}"
        )

    def _given_group_tag_mapping(self, connection, tag=None):
        group_tag_mapping = GroupTagMapping.objects.create(
            group_email=f"{connection}@zentral.com",
            connection=connection)
        if tag:
            group_tag_mapping.tags.set([tag])

        return group_tag_mapping

    def _assert_audit_event_not_send(self, post_event, callbacks):
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def _assert_audit_event_send(self, group_tag_mapping, post_event, callbacks,
                                 action: AuditEvent.Action, prev_value: dict[str, str] = None):
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]

        expected_payload = {'action': action.value,
                            'object': {
                                'model': 'google_workspace.grouptagmapping',
                                'pk': str(group_tag_mapping.pk)}}
        match action:
            case AuditEvent.Action.CREATED:
                expected_payload["object"].update({'new_value': group_tag_mapping.serialize_for_event()})
            case AuditEvent.Action.UPDATED:
                expected_payload["object"].update({'prev_value': prev_value})
                expected_payload["object"].update({'new_value': group_tag_mapping.serialize_for_event()})
            case AuditEvent.Action.DELETED:
                expected_payload["object"].update({'prev_value': prev_value})

        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"google_workspace_group_tag_mapping": [str(group_tag_mapping.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["google_workspace", "zentral"])

    def _connection_to_dict(self, connection: Connection):
        return {
                'id': str(connection.pk),
                'name': connection.name,
                'created_at': connection.created_at.isoformat(),
                'updated_at': connection.updated_at.isoformat()
            }

    def _connection_to_list(self, connection: Connection):
        return [self._connection_to_dict(connection)]

    def _group_tag_mapping_to_dict(self, group_tag_mapping: GroupTagMapping):
        return {
            'id': str(group_tag_mapping.pk),
            'group_email': group_tag_mapping.group_email,
            'connection': str(group_tag_mapping.connection.pk),
            'tags': [t.pk for t in group_tag_mapping.tags.all()],
            'created_at': group_tag_mapping.created_at.isoformat(),
            'updated_at': group_tag_mapping.updated_at.isoformat()
        }

    def _group_tag_mapping_to_list(self, group_tag_mapping: GroupTagMapping):
        return [self._group_tag_mapping_to_dict(group_tag_mapping)]

    def _group_tag_mapping_request(self, connection_pk: uuid, group_email: str, tag_pk: int):
        return {
            'connection': str(connection_pk),
            'group_email': group_email,
            'tags': [tag_pk]
        }

    # SyncTagsView

    def test_user_group_tag_mappings_task_unauthorized(self):
        connection = self._given_connection()
        response = self.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_user_group_tag_mappings_task_permission_denied(self):
        connection = self._given_connection()
        self.login()
        response = self.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_user_group_tag_mappings_task_devices(self):
        connection = self._given_connection()
        self.login("google_workspace.view_connection")
        response = self.client.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])

    # ConnectionList

    def test_list_connections_unauthorized(self):
        response = self.get(reverse("google_workspace_api:connections"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_connections_permission_denied(self):
        response = self.get(reverse("google_workspace_api:connections"))
        self.assertEqual(response.status_code, 403)

    def test_list_connections_method_not_allowed(self):
        self.set_permissions("google_workspace.add_connection")
        response = self.post(reverse("google_workspace_api:connections"), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "POST" not allowed.'})

    def test_list_connections(self):
        self.set_permissions("google_workspace.view_connection")
        connection = self._given_connection()
        response = self.get(reverse("google_workspace_api:connections"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._connection_to_list(connection))

    def test_list_connections_by_name_no_results(self):
        self.set_permissions("google_workspace.view_connection")
        response = self.get(reverse("google_workspace_api:connections") + f"?name={get_random_string(12)}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_list_connections_by_name(self):
        self.set_permissions("google_workspace.view_connection")
        connection = self._given_connection()
        response = self.get(reverse("google_workspace_api:connections") + f"?name={connection.name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._connection_to_list(connection))

    # ConnectionDetail

    def test_connection_unauthorized(self):
        connection = self._given_connection()
        response = self.get(reverse("google_workspace_api:connection", args=(connection.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_connection_permission_denied(self):
        connection = self._given_connection()
        response = self.get(reverse("google_workspace_api:connection", args=(connection.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_connection_method_not_allowed(self):
        connection = self._given_connection()
        self.set_permissions("google_workspace.change_connection")
        response = self.put(reverse("google_workspace_api:connection", args=(connection.pk,)), {})
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "PUT" not allowed.'})

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection_unhealthy(self, build):
        self.set_permissions("google_workspace.view_connection")
        connection = self._given_connection()

        build.return_value.groups.return_value.list.return_value.execute.side_effect = HttpError(Mock(status=403), b"")

        response = self.get(reverse("google_workspace_api:connection", args=(connection.pk,)))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                'id': str(connection.pk),
                'name': connection.name,
                'healthy': False,
                'created_at': connection.created_at.isoformat(),
                'updated_at': connection.updated_at.isoformat()
            }
        )

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_connection(self, build):
        self.set_permissions("google_workspace.view_connection")
        connection = self._given_connection()

        build.return_value.groups.return_value.list.return_value.execute.side_effect = HttpError(Mock(status=404), b"")

        response = self.get(reverse("google_workspace_api:connection", args=(connection.pk,)))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                'id': str(connection.pk),
                'name': connection.name,
                'healthy': True,
                'created_at': connection.created_at.isoformat(),
                'updated_at': connection.updated_at.isoformat()
            }
        )

    # GroupTagMappingList

    def test_list_group_tag_mappings_unauthorized(self):
        response = self.get(reverse("google_workspace_api:group_tag_mappings"), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_list_group_tag_mappings_permission_denied(self):
        response = self.get(reverse("google_workspace_api:group_tag_mappings"))
        self.assertEqual(response.status_code, 403)

    def test_list_group_tag_mappings(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        connection = self._given_connection()
        other_connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        other_group_tag_mapping = self._given_group_tag_mapping(other_connection, other_tag)
        expected_mappings = [
            self._group_tag_mapping_to_dict(group_tag_mapping),
            self._group_tag_mapping_to_dict(other_group_tag_mapping)
        ]

        response = self.get(reverse("google_workspace_api:group_tag_mappings"))

        self.assertEqual(response.status_code, 200)

        actual_mappings = response.json()
        self.assertEqual(len(actual_mappings), len(expected_mappings))
        self.assertTrue(all(expected in actual_mappings for expected in expected_mappings))

    def test_list_group_tag_mappings_by_group_email_no_result(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        response = self.get(
            reverse("google_workspace_api:group_tag_mappings") + f"?group_email={get_random_string(12)}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_list_group_tag_mappings_by_group_email(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        connection = self._given_connection()
        other_connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        self._given_group_tag_mapping(other_connection, other_tag)

        response = self.get(
            reverse("google_workspace_api:group_tag_mappings") + f"?group_email={group_tag_mapping.group_email}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), self._group_tag_mapping_to_list(group_tag_mapping))

    def test_list_group_tag_mappings_by_connection_no_result(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        connection = self._given_connection()
        response = self.get(reverse("google_workspace_api:group_tag_mappings") + f"?connection_id={connection.id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])

    def test_list_group_tag_mappings_by_connection(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        connection = self._given_connection()
        other_connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        self._given_group_tag_mapping(other_connection, other_tag)

        response = self.get(reverse("google_workspace_api:group_tag_mappings") + f"?connection_id={connection.id}")

        self.assertEqual(response.status_code, 200)

        self.assertEqual(response.json(), self._group_tag_mapping_to_list(group_tag_mapping))

    def test_list_group_tag_mappings__method_not_allowed(self):
        self.set_permissions("google_workspace.delete_grouptagmapping")
        response = self.delete(reverse("google_workspace_api:group_tag_mappings"))
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.json(), {'detail': 'Method "DELETE" not allowed.'})

    # GroupTagMappingDetail

    # get group tag mapping

    def test_get_group_tag_mapping_unauthorized(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)

        response = self.get(
            reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk, )),
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_get_group_tag_mapping_permission_denied(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)

        response = self.get(reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk, )))
        self.assertEqual(response.status_code, 403)

    def test_get_group_tag_mapping(self):
        self.set_permissions("google_workspace.view_grouptagmapping")
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)

        response = self.get(reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk, )))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._group_tag_mapping_to_dict(group_tag_mapping)
        )

    # create group tag mapping

    def test_create_group_tag_mapping_unauthorized(self):
        response = self.post(reverse("google_workspace_api:group_tag_mappings"), {}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_create_group_tag_mapping_permission_denied(self):
        response = self.post(reverse("google_workspace_api:group_tag_mappings"), {})
        self.assertEqual(response.status_code, 403)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_create_group_tag_mapping_unkown_tag(self, build):
        self.set_permissions("google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        group_email = self._given_email()

        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]
        }

        response = self.post(
            reverse("google_workspace_api:group_tag_mappings"),
            self._group_tag_mapping_request(connection.pk, group_email, 1)
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'tags': ['Invalid pk "1" - object does not exist.']}
        )

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_create_group_tag_mapping_unkown_email(self, build):
        self.set_permissions("google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        group_email = self._given_email()
        tag = self._given_tag()

        build.return_value.groups.return_value.get.side_effect = HttpError(Mock(status=404), b"")

        response = self.post(
            reverse("google_workspace_api:group_tag_mappings"),
            self._group_tag_mapping_request(connection.pk, group_email, tag.pk)
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'group_email': ['Group email not found for this connection.']}
        )

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_group_tag_mapping(self, post_event, build):
        self.set_permissions("google_workspace.add_grouptagmapping")
        connection = self._given_connection()
        group_email = self._given_email()
        tag = self._given_tag()

        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                reverse("google_workspace_api:group_tag_mappings"),
                self._group_tag_mapping_request(connection.pk, group_email, tag.pk)
            )

        group_tag_mapping = GroupTagMapping.objects.get(group_email=group_email)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(
            response.json(),
            self._group_tag_mapping_to_dict(group_tag_mapping)
        )

        self._assert_audit_event_send(group_tag_mapping, post_event, callbacks, AuditEvent.Action.CREATED)

    # update group tag mapping

    def test_update_group_tag_mapping_unauthorized(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        response = self.put(
            reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)),
            {},
            include_token=False
        )
        self.assertEqual(response.status_code, 401)

    def test_update_group_tag_mapping_permission_denied(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        response = self.put(reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)), {})
        self.assertEqual(response.status_code, 403)

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_group_tag_mapping_cannot_be_updated(self, post_event, build):
        self.set_permissions("google_workspace.change_grouptagmapping")

        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        group_email = self._given_email()

        build.return_value.groups.return_value.get.side_effect = HttpError(Mock(status=404), b"")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk, )),
                self._group_tag_mapping_request(connection.pk, group_email, tag.pk)
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),  {'group_email': ['Group email not found for this connection.']})

        self._assert_audit_event_not_send(post_event, callbacks)

    @patch('zentral.contrib.google_workspace.api_client.build')
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_group_tag_mapping(self, post_event, build):
        self.set_permissions("google_workspace.change_grouptagmapping")

        connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        prev_value = group_tag_mapping.serialize_for_event()

        group_email = self._given_email()

        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": group_email}]
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(
                reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)),
                self._group_tag_mapping_request(connection.pk, group_email, other_tag.pk)
            )

        group_tag_mapping.refresh_from_db()
        self.assertEqual(group_tag_mapping.group_email, group_email)
        group_tag_mapping.tags.get(id=other_tag.pk)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            self._group_tag_mapping_to_dict(group_tag_mapping)
        )

        self._assert_audit_event_send(group_tag_mapping, post_event, callbacks, AuditEvent.Action.UPDATED, prev_value)

    # delete group tag mapping

    def test_delete_group_tag_mapping_unauthorized(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)

        response = self.delete(
            reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)),
            include_token=False
        )

        self.assertEqual(response.status_code, 401)

    def test_delete_group_tag_mapping_permission_denied(self):
        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)

        response = self.delete(reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)))

        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_group_tag_mapping(self, post_event):
        self.set_permissions("google_workspace.delete_grouptagmapping")

        connection = self._given_connection()
        tag = self._given_tag()
        group_tag_mapping = self._given_group_tag_mapping(connection, tag)
        prev_value = group_tag_mapping.serialize_for_event()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("google_workspace_api:group_tag_mapping", args=(group_tag_mapping.pk,)))

        self.assertFalse(GroupTagMapping.objects.filter(pk=group_tag_mapping.pk).exists())
        self.assertEqual(response.status_code, 204)

        self._assert_audit_event_send(group_tag_mapping, post_event, callbacks, AuditEvent.Action.DELETED, prev_value)
