import json
from django.test import TestCase
from unittest.mock import patch, Mock
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import (Tag,
                                              MachineSnapshotCommit,
                                              Source,
                                              PrincipalUserSource,
                                              MachineTag,
                                              Taxonomy,
                                              MetaBusinessUnit)
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping
from zentral.contrib.google_workspace.utils import sync_group_tag_mappings
from zentral.contrib.inventory.events import MachineTagEvent


class UtilsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.principal_user_source = PrincipalUserSource.objects.create(type=PrincipalUserSource.INVENTORY)
        cls.source = Source.objects.create(module="source module", name="source name")

    def _given_user_email(self):
        return f"{get_random_string(12)}@zentral.com"

    def _given_serial_number(self):
        return f"sn_{get_random_string(8)}"

    def _force_machine(self, user_email, serial_number=None):
        if not serial_number:
            serial_number = self._given_serial_number()
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {'module': 'io.zentral.tests', 'name': 'zentral'},
            "serial_number": serial_number,
            "principal_user": {
                "source": {"type": "LOGGED_IN_USER", "properties": {"method": "System Configuration"}},
                "unique_id": user_email,
                "principal_name": get_random_string(12),
                "display_name": get_random_string(12),
            },
        })
        return serial_number

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

    def _given_tag(self, taxomony=None):
        meta_business_unit = None
        if taxomony:
            meta_business_unit = taxomony.meta_business_unit
        return Tag.objects.create(
            name=f"tag_{get_random_string(5)}",
            taxonomy=taxomony,
            meta_business_unit=meta_business_unit
        )

    def _given_taxonomy(self):
        unit = MetaBusinessUnit.objects.create(
            name=f"business_unit_{get_random_string(5)}"
        )
        return Taxonomy.objects.create(
            meta_business_unit=unit,
            name=f"taxonomy_{get_random_string(5)}"
        )

    def _given_group_tag_mapping(self, connection, tag, group_email=None):
        if not group_email:
            group_email = f"{connection}@zentral.com"
        group_tag_mapping = GroupTagMapping.objects.create(
            group_email=group_email,
            connection=connection)
        if tag:
            if isinstance(tag, Tag):
                tag = [tag]
            group_tag_mapping.tags.set(tag)

        return group_tag_mapping

    def _given_machine_tag(self, serial_number, tag=None):
        return MachineTag.objects.create(serial_number=serial_number, tag=tag)

    def _expected_machine_tag_event_payload(self, tag, action="added", taxonomy=None):
        d = {
                "action": action,
                "tag": {"pk": tag.pk, "name": tag.name}
            }
        if taxonomy:
            d["taxonomy"] = {"pk": taxonomy.pk, "name": taxonomy.name}
        return d

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_adds_tag(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{'email': user_email}]}

        # snapshots for one device
        serial_number = self._force_machine(user_email)

        # one group tag mapping
        connection = self._given_connection()
        taxonomy = self._given_taxonomy()
        tag = self._given_tag(taxonomy)
        self._given_group_tag_mapping(connection, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number=serial_number, tag_id=tag.pk)
        self.assertTrue(actual.exists())

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            self._expected_machine_tag_event_payload(tag, taxonomy=taxonomy)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], serial_number)
        self.assertEqual(metadata["tags"], ["machine"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_adds_existing_tag(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{'email': user_email}]}

        # snapshots for one device
        serial_number = self._force_machine(user_email)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        self._given_group_tag_mapping(connection, tag)

        # device has tag
        self._given_machine_tag(serial_number, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number=serial_number, tag_id=tag.pk)
        self.assertEqual(actual.count(), 1)

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_removes_existing_tag(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        other_group_email = "other_group@zentral.com"

        def group_member_list_side_effect(groupKey, pageToken):
            mock = Mock()
            if groupKey == other_group_email:
                mock.execute.return_value = {"members": []}
            else:
                mock.execute.return_value = {"members": [{'email': user_email}]}
            return mock
        build.return_value.members.return_value.list.side_effect = group_member_list_side_effect

        # snapshots for one device
        serial_number = self._force_machine(user_email)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        # given tag is assigned to group user is not part of
        self._given_group_tag_mapping(connection, tag, other_group_email)
        # empty group tag mapping for users group
        self._given_group_tag_mapping(connection, None)

        # device has tag
        self._given_machine_tag(serial_number, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number=serial_number, tag_id=tag.pk)
        self.assertEqual(actual.count(), 0)

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            self._expected_machine_tag_event_payload(tag, "removed")
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], serial_number)
        self.assertEqual(metadata["tags"], ["machine"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_removes_non_existing_tag(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        other_group_email = "other_group@zentral.com"

        def group_member_list_side_effect(groupKey, pageToken):
            mock = Mock()
            if groupKey == other_group_email:
                mock.execute.return_value = {"members": []}
            else:
                mock.execute.return_value = {"members": [{'email': user_email}]}
            return mock
        build.return_value.members.return_value.list.side_effect = group_member_list_side_effect

        # snapshots for one device
        serial_number = self._force_machine(user_email)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        # given tag is assigned to group user is not part of
        self._given_group_tag_mapping(connection, tag, other_group_email)
        # empty group tag mapping for users group
        self._given_group_tag_mapping(connection, None)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number=serial_number, tag_id=tag.pk)
        self.assertEqual(actual.count(), 0)

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_add_multiple_devices(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{'email': user_email}]}

        # multiple devices
        serial_number = self._given_serial_number()
        other_serial_number = self._given_serial_number()

        # multiple snapshots for devices
        for _ in range(0, 5):
            self._force_machine(user_email, serial_number)
            self._force_machine(user_email, other_serial_number)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        self._given_group_tag_mapping(connection, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number__in=[serial_number, other_serial_number], tag_id=tag.pk)
        self.assertEqual(actual.count(), 2)

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 2)

        for call_args in post_event.call_args_list:
            event = call_args.args[0]
            self.assertIsInstance(event, MachineTagEvent)
            self.assertEqual(
                event.payload,
                self._expected_machine_tag_event_payload(tag)
            )

            metadata = event.metadata.serialize()
            self.assertTrue(metadata["machine_serial_number"] == serial_number
                            or metadata["machine_serial_number"] == other_serial_number)
            self.assertEqual(metadata["tags"], ["machine"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_sync_different_groups(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        other_user_email = self._given_user_email()
        other_group_email = "other_group@zentral.com"

        def group_member_list_side_effect(groupKey, pageToken):
            mock = Mock()
            if groupKey == other_group_email:
                mock.execute.return_value = {"members": [{'email': user_email}, {'email': other_user_email}]}
            else:
                mock.execute.return_value = {"members": [{'email': user_email}]}
            return mock
        build.return_value.members.return_value.list.side_effect = group_member_list_side_effect

        # a device for each user
        serial_number = self._force_machine(user_email)
        other_serial_number = self._force_machine(other_user_email)

        # one group tag mapping for each group
        connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        self._given_group_tag_mapping(connection, [tag, other_tag])
        self._given_group_tag_mapping(connection, other_tag, other_group_email)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(tag_id=other_tag.pk)
        self.assertEqual(actual.count(), 2)
        actual = MachineTag.objects.filter(tag_id=tag.pk)
        self.assertEqual(actual.count(), 1)

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 3)

        for call_args in post_event.call_args_list:
            event = call_args.args[0]
            self.assertIsInstance(event, MachineTagEvent)
            self.assertEqual(event.payload["action"], "added")
            self.assertTrue(event.payload["tag"]["pk"] == tag.pk
                            or event.payload["tag"]["pk"] == other_tag.pk)

            metadata = event.metadata.serialize()
            self.assertTrue(metadata["machine_serial_number"] == serial_number
                            or metadata["machine_serial_number"] == other_serial_number)
            self.assertEqual(metadata["tags"], ["machine"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_exclude_not_managed_users(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        other_user_email = self._given_user_email()

        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{'email': user_email}]}

        # a device for each user
        serial_number = self._force_machine(user_email)
        self._force_machine(other_user_email)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        self._given_group_tag_mapping(connection, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        actual = MachineTag.objects.filter(tag_id=tag.pk)
        self.assertEqual(actual.count(), 1)

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            self._expected_machine_tag_event_payload(tag)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["machine_serial_number"], serial_number)
        self.assertEqual(sorted(metadata["tags"]), ["machine"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch('zentral.contrib.google_workspace.api_client.build')
    def test_sync_group_tag_mappings_exclude_not_managed_tags(self, build, post_event):
        # Given
        user_email = self._given_user_email()
        build.return_value.members.return_value.list.return_value.execute.return_value = {
            "members": [{'email': user_email}]}

        # snapshots for one device
        serial_number = self._force_machine(user_email)

        # one group tag mapping
        connection = self._given_connection()
        tag = self._given_tag()
        other_tag = self._given_tag()
        self._given_group_tag_mapping(connection, other_tag)

        # device has tag
        self._given_machine_tag(serial_number, tag)

        # When
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            sync_group_tag_mappings(connection)

        # Then
        actual = MachineTag.objects.filter(serial_number=serial_number, tag_id=tag.pk)
        self.assertTrue(actual.exists())

        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertFalse(event.payload["tag"]["pk"] == tag.pk)
        self.assertTrue(event.payload["tag"]["pk"] == other_tag.pk)
