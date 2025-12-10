import uuid
import json
from django.test import TestCase
from django.utils.crypto import get_random_string
from unittest.mock import patch
from zentral.contrib.google_workspace.models import Connection
from zentral.contrib.google_workspace.tasks import sync_group_tag_mappings_task


class SyncGroupTagMappingsTaskTestCase(TestCase):

    def _given_connection(self):
        name = get_random_string(12)
        client_config = json.dumps({"web": {}})
        connection = Connection.objects.create(name=name)
        connection.set_client_config(client_config)
        connection.save()

        return connection

    def _given_serialized_event_request(self):
        return {
            "user_agent": f"TestAgent:{get_random_string(6)}",
            "ip": "127.0.0.1",
            "method": "POST",
            "path": "/test/",
            "view": "TestView"
        }

    @patch("zentral.contrib.google_workspace.tasks.sync")
    def test_sync_group_tag_mappings_task(self, sync):
        # Given
        connection = self._given_connection()
        count = {
            "added": 1,
            "removed": 1
        }
        sync.return_value = count
        event_request = self._given_serialized_event_request()

        # When
        actual = sync_group_tag_mappings_task(connection.pk, event_request)

        # Then
        expected = {
            "connection": {"pk": str(connection.pk), "name": connection.name},
            "machine_tags": count
        }
        self.assertEqual(actual, expected)

    def test_sync_group_tag_mappings_task_no_connection(self):
        # Given
        connection_pk = uuid.uuid4()

        # When
        actual = sync_group_tag_mappings_task(connection_pk)

        # Then
        expected = {
            "connection_not_found": {"pk": str(connection_pk)}
        }
        self.assertEqual(actual, expected)
