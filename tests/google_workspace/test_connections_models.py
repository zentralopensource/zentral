from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.google_workspace.models import GroupTagMapping, Connection
from unittest.mock import patch


class ConnectionsModelsTestCase(TestCase):

    def _given_connection(self, user_info="{}"):
        name = get_random_string(12)
        client_config = """{"web":{}}"""
        connection = Connection.objects.create(name=name)
        if user_info:
            connection.set_user_info(user_info)
        connection.set_client_config(client_config)
        connection.save()

        return connection

    def _given_group_tag_mapping(self, connection):
        group_email = f"{get_random_string(12)}@zentral.io"
        return GroupTagMapping.objects.create(group_email=group_email, connection=connection)

    def test_group_tag_mapping_serialize_for_event_keys_only(self):
        # Given
        connection = self._given_connection()
        group_tag_mapping = self._given_group_tag_mapping(connection)

        # When
        actual = group_tag_mapping.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": str(group_tag_mapping.pk),
            "group_email": group_tag_mapping.group_email
        })

    def test_connection_get_user_info(self):
        # Given
        user_config = "{}"
        connection = self._given_connection(user_config)

        # When
        actual = connection.get_user_info()

        # Then
        self.assertEqual(actual, user_config)

    def test_connection_set_user_info(self):
        # Given
        user_info = "{}"
        connection = self._given_connection(None)

        # When
        with patch('zentral.contrib.google_workspace.models.encrypt_str') as encrypt_str:
            connection.set_user_info(user_info)

            # Then
            encrypt_str.assert_called_once_with(
                user_info, model='google_workspace.connection', pk=str(connection.pk), field='user_info')

    def test_connection_set_user_info_none(self):
        # Given
        user_info = None
        connection = self._given_connection()

        # When
        with patch('zentral.contrib.google_workspace.models.encrypt_str') as encrypt_str:
            connection.set_user_info(user_info)

            # Then
            self.assertIsNone(connection.get_user_info())
            encrypt_str.assert_not_called()

    def test_connection_rewrap_secrets(self):
        # Given
        connection = self._given_connection()
        user_info = connection.get_user_info()
        client_config = connection.get_client_config()

        # When
        connection.rewrap_secrets()

        # Then
        self.assertEqual(user_info, connection.get_user_info())
        self.assertEqual(client_config, connection.get_client_config())
