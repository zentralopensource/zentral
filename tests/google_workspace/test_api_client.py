import uuid
import json
from django.test import TestCase
from unittest.mock import patch, Mock
from django.utils.crypto import get_random_string
from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.api_client import APIClient, APIClientError, _AdminSDKClient
from django.core.cache import cache
from googleapiclient.errors import HttpError


class ApiClientTestCase(TestCase):
    class _TestAPIClient(APIClient):
        def is_healthy(self, error_message_callback=None):
            return super().is_healthy(error_message_callback)

        def iter_group_members(self, group_key):
            return super().iter_group_members(group_key)

        def iter_groups(self):
            return super().iter_groups()

        def get_group(self, group_key):
            return super().get_group(group_key)

        def _build_service(self, sdk, api):
            return super()._build_service(sdk, api)

    def _given_connection(self):
        name = get_random_string(12)
        client_config = json.dumps({"web": {}})
        user_info = json.dumps({
            "refresh_token": get_random_string(12),
            "client_id": get_random_string(12),
            "client_secret": get_random_string(12)
        })
        connection = Connection.objects.create(name=name)
        connection.set_client_config(client_config)
        connection.set_user_info(user_info)
        connection.save()

        return connection

    def _given_cloud_id_connection(self):
        name = get_random_string(12)
        customer_id = f"C{get_random_string(5)}"
        connection = Connection.objects.create(
            name=name,
            customer_id=customer_id,
            type=Connection.Type.SERVICE_ACCOUNT_CLOUD_IDENTITY
        )

        return connection

    def test_from_oauth2_state_no_cached_connection(self):
        with self.assertRaisesMessage(APIClientError, "Invalid OAUTH2 state"):
            APIClient.from_oauth2_state("unknown_state")

    def test_from_oauth2_state_no_connection(self):
        state = get_random_string(5)
        cache_key = f"{_AdminSDKClient.oauth2_state_cache_key_prefix}{state}"
        cache.set(cache_key, str(uuid.uuid4()), 3600)

        with self.assertRaisesMessage(APIClientError, "Invalid Google Workspace connection"):
            APIClient.from_oauth2_state(state)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_get_group_error(self, build):
        build.return_value.groups.side_effect = HttpError(Mock(status=403), b"")
        for api_client in [
            APIClient.from_connection(self._given_connection()),
            APIClient.from_connection(self._given_cloud_id_connection())
        ]:
            with self.assertRaises(HttpError):
                api_client.get_group("no-reply@zentral.com")

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_iter_group_members(self, build):
        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{"email": "no-reply@zentral.com", 'type': "USER"},
                        {"email": "any-group@zentral.com", 'type': "GROUP"}]}
        connection = self._given_connection()

        members = [member["email"] for member in APIClient.from_connection(connection).iter_group_members("group")]

        self.assertEqual(len(members), 1)
        self.assertEqual(members[0], "no-reply@zentral.com")

    def test_abstract_methods_for_coverage(self):
        client = self._TestAPIClient()
        client.is_healthy()
        client.iter_groups()
        client.iter_group_members(None)
        client.get_group(None)
        client._build_service(None, None)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_is_healthy_callback(self, build):
        build.return_value.groups.side_effect = HttpError(Mock(status=403), b"")
        connection = self._given_cloud_id_connection()
        callback = Mock()
        callback.return_value = None

        api_client = APIClient.from_connection(connection)
        api_client.is_healthy(callback)

        self.assertTrue(callback.called)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_iter_groups(self, build):
        email = f"{get_random_string(12)}@zentral.com"
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": email}]
        }
        connection = self._given_connection()
        api_client = APIClient.from_connection(connection)
        emails = [group["email"] for group in api_client.iter_groups()]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0], email)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_iter_groups_cloud_id(self, build):
        email = f"{get_random_string(12)}@zentral.com"
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [
                {
                    "groupKey": {"id": email}
                }
            ]
        }
        connection = self._given_cloud_id_connection()
        api_client = APIClient.from_connection(connection)
        emails = [group["email"] for group in api_client.iter_groups()]
        self.assertEqual(len(emails), 1)
        self.assertEqual(emails[0], email)
