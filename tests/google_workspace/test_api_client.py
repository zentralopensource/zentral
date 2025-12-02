import uuid
import json
from django.test import TestCase
from unittest.mock import patch, Mock
from django.utils.crypto import get_random_string
from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.api_client import APIClient, APIClientError
from django.core.cache import cache
from googleapiclient.errors import HttpError


class ApiClientTestCase(TestCase):

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

    def test_from_oauth2_state_no_cached_connection(self):
        with self.assertRaisesMessage(APIClientError, "Invalid OAUTH2 state"):
            APIClient.from_oauth2_state("unkown state")

    def test_from_oauth2_state_no_connection(self):
        state = get_random_string(5)
        cache_key = f"{APIClient.oauth2_state_cache_key_prefix}{state}"
        cache.set(cache_key, str(uuid.uuid4()), 3600)

        with self.assertRaisesMessage(APIClientError, "Invalid Google Workspace connection"):
            APIClient.from_oauth2_state(state)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_get_group_404_error_response(self, build):
        build.return_value.groups.return_value.get.side_effect = HttpError(Mock(status=404), b"")
        connection = self._given_connection()

        api_client = APIClient.from_connection(connection)
        actual = api_client.get_group("no-reply@zentral.com")

        self.assertIsNone(actual)

    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_get_group_non_404_error_response(self, build):
        build.return_value.groups.return_value.get.side_effect = HttpError(Mock(status=403), b"")
        connection = self._given_connection()

        with self.assertRaises(HttpError):
            api_client = APIClient.from_connection(connection)
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
