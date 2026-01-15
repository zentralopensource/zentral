from functools import reduce
import json
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.models import MachineSnapshotCommit, MachineTag, Tag, Taxonomy


class InventoryAPITests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            "{}@zentral.io".format(get_random_string(12)),
            get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.user)
        cls.url = reverse("inventory_api:update_machine_tags")

    # utility methods

    def _set_permissions(self, *permissions):
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

    def _set_required_permission(self):
        self._set_permissions("inventory.add_tag", "inventory.add_taxonomy",
                              "inventory.add_machinetag", "inventory.delete_machinetag")

    def _post_data(self, data, content_type, include_token=True):
        kwargs = {"content_type": content_type}
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return self.client.post(self.url, data, **kwargs)

    def _post_json_data(self, data, include_token=True):
        data = json.dumps(data)
        return self._post_data(data, "application/json", include_token)

    def _force_machine(self):
        serial_number = get_random_string(12)
        unique_id = get_random_string(12)
        principal_name = get_random_string(12)
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {'module': 'io.zentral.tests', 'name': 'zentral'},
            "serial_number": serial_number,
            "principal_user": {
                "source": {"type": "LOGGED_IN_USER", "properties": {"method": "System Configuration"}},
                "unique_id": unique_id,
                "principal_name": principal_name,
                "display_name": get_random_string(12),
            },
        })
        return serial_number, unique_id, principal_name

    def _force_machine_tags(self, serial_number, number):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag_names = []
        for i in range(number):
            tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
            MachineTag.objects.create(serial_number=serial_number, tag=tag)
            tag_names.append(tag.name)
        return taxonomy.name, tag_names

    # tests

    def test_post_unauthorized(self):
        response = self._post_json_data({}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_post_permission_denied(self):
        response = self._post_json_data({}, include_token=True)
        self.assertEqual(response.status_code, 403)

    def test_post_empty_tags(self):
        self._set_required_permission()
        response = self._post_json_data({
            "principal_users": {"unique_ids": ["yolo"]}
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'operations': ['This field is required.']})

    def test_post_principal_users_or_serial_numbers(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "SET", "taxonomy": "yol", "names": []},
                           {"kind": "SET", "taxonomy": "lo", "names": ["1"]}]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'non_field_errors': ['principal_users and serial_numbers cannot be both empty.']}
        )

    def test_post_add_operation_empty_names(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "ADD", "taxonomy": "yol", "names": []}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'names': ['This list may not be empty for ADD operations']}}}
        )

    def test_post_remove_operation_empty_names(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "REMOVE", "names": []}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'names': ['This list may not be empty for REMOVE operations']}}}
        )

    def test_post_set_operation_empty_taxonomy(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "SET", "taxonomy": None, "names": ["yolo"]}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'taxonomy': ['This field is required for SET operations']}}}
        )

    def test_post_remove_operation_non_empty_taxonomy(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "REMOVE", "taxonomy": "fomo", "names": ["yolo"]}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'taxonomy': ['This field may not be set for REMOVE operations']}}}
        )

    def test_post_empty_unique_ids_and_principal_names(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "SET", "taxonomy": "yol", "names": []},
                           {"kind": "SET", "taxonomy": "lo", "names": ["1"]}],
            "principal_users": {}
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'principal_users': {
                 'non_field_errors': ['Unique ids and principal names cannot be both empty.']
             }}
        )

    def test_post_empty_serial_numbers(self):
        self._set_required_permission()
        response = self._post_json_data({
            "operations": [{"kind": "SET", "taxonomy": "yol", "names": []},
                           {"kind": "SET", "taxonomy": "lo", "names": ["1"]}],
            "serial_numbers": []
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'serial_numbers': ['This list may not be empty.']}
        )

    def test_post_set_no_change(self):
        self._set_required_permission()
        # non matching machine
        serial_number, _, _ = self._force_machine()
        principal_name = get_random_string(12)
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        response = self._post_json_data({
            "operations": [{"kind": "SET", "taxonomy": taxonomy_name, "names": [tag_name]}],
            "principal_users": {"principal_names": [principal_name]}
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'machines': {'found': 0}, 'tags': {'added': 0, 'removed': 0}}
        )
        self.assertEqual(
            MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name,
                                      tag__name=tag_name,
                                      serial_number=serial_number).count(),
            0
        )

    def test_post_add_existing_taxonomy_tag_without_taxonomy(self):
        self._set_required_permission()
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        response = self._post_json_data({
            "operations": [{"kind": "ADD", "names": [tag.name]}],  # No taxonomy but existing tag with one
            "serial_numbers": [get_random_string(12)],
        })
        self.assertEqual(
            response.json(),
            {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}}
        )

    def test_post_set_existing_taxonomy_tag_with_taxonomy(self):
        self._set_required_permission()
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(name=get_random_string(12))
        response = self._post_json_data({
            "operations": [{"kind": "SET",
                            "taxonomy": taxonomy.name,
                            "names": [tag.name]}],  # With taxonomy but existing tag doesn't have one
            "serial_numbers": [get_random_string(12)],
        })
        self.assertEqual(
            response.json(),
            {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_add_one_tag(self, post_event):
        self._set_required_permission()
        # non matching machine
        self._force_machine()
        # matching machine
        serial_number, _, principal_name = self._force_machine()
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data({
                "operations": [{"kind": "SET", "taxonomy": taxonomy_name, "names": [tag_name]}],
                "principal_users": {"principal_names": [principal_name]}
            })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}}
        )
        self.assertEqual(
            MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name,
                                      tag__name=tag_name,
                                      serial_number=serial_number).count(),
            1
        )
        # events
        self.assertEqual(len(callbacks), 1)
        event, = [c.args[0] for c in post_event.call_args_list]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            {'action': 'added',
             'tag': {'name': tag_name, 'pk': Tag.objects.get(name=tag_name).pk},
             'taxonomy': {'name': taxonomy_name, 'pk': Taxonomy.objects.get(name=taxonomy_name).pk}}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_add_one_remove_three(self, post_event):
        self._set_required_permission()
        # non matching machine
        self._force_machine()
        # matching machine
        serial_number, unique_id, _ = self._force_machine()
        # 1 taxonomy with 1 tag
        taxonomy_name0, tag_names0 = self._force_machine_tags(serial_number, 1)
        # 1 taxonomy with 2 tags
        taxonomy_name1, _ = self._force_machine_tags(serial_number, 2)
        new_taxonomy_tag_name1 = get_random_string(12)
        # 1 taxonomy with 1 tag
        taxonomy_name2, _ = self._force_machine_tags(serial_number, 1)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data({
                "operations": [
                    {"kind": "SET", "taxonomy": taxonomy_name0, "names": [tag_names0[0]]},
                    {"kind": "SET", "taxonomy": taxonomy_name1, "names": [new_taxonomy_tag_name1]},
                    {"kind": "SET", "taxonomy": taxonomy_name2, "names": []}
                ],
                "principal_users": {"unique_ids": [unique_id]}
            })
        self.assertEqual(
            response.json(),
            {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 3}}
        )
        self.assertEqual(
            set(MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name0,
                                          serial_number=serial_number).values_list("tag__name", flat=True)),
            set(tag_names0)
        )
        self.assertEqual(
            set(MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name1,
                                          serial_number=serial_number).values_list("tag__name", flat=True)),
            {new_taxonomy_tag_name1}
        )
        self.assertEqual(
            MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name2,
                                      serial_number=serial_number).values_list("tag__name", flat=True).count(),
            0
        )
        # events
        self.assertEqual(len(callbacks), 4)
        self.assertEqual(len(post_event.call_args_list), 4)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_multiple_add_one(self, post_event):
        self._set_required_permission()
        # 3 matching machines
        serial_number0, _, principal_name0 = self._force_machine()
        serial_number1, unique_id1, principal_name1 = self._force_machine()
        serial_number2, unique_id2, _ = self._force_machine()
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data({
                "operations": [{"kind": "SET", "taxonomy": taxonomy_name, "names": [tag_name]}],
                "principal_users": {"unique_ids": [unique_id1, unique_id2],
                                    "principal_names": [principal_name0, principal_name1]}
            })
        self.assertEqual(
            response.json(),
            {'machines': {'found': 3}, 'tags': {'added': 3, 'removed': 0}}
        )
        self.assertEqual(
            set(MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name, tag__name=tag_name)
                                  .values_list("serial_number", flat=True)),
            {serial_number0, serial_number1, serial_number2}
        )
        # events
        self.assertEqual(len(callbacks), 3)
        self.assertEqual(len(post_event.call_args_list), 3)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_add_three_tags(self, post_event):
        self._set_required_permission()
        serial_number, _, principal_name = self._force_machine()
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number).count(), 0)
        tag_name_1 = get_random_string(12)
        tag_name_2 = get_random_string(12)
        taxonomy_name_3 = get_random_string(12)
        tag_name_3 = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data({
                "operations": [{"kind": "ADD", "names": [tag_name_1, tag_name_2]},
                               {"kind": "ADD", "taxonomy": taxonomy_name_3, "names": [tag_name_3]}],
                "principal_users": {"principal_names": [principal_name]}
            })
        self.assertEqual(
            response.json(),
            {"machines": {"found": 1}, "tags": {"added": 3, "removed": 0}}
        )
        self.assertEqual(
            set(mt.tag for mt in MachineTag.objects.select_related("tag").filter(tag__taxonomy__isnull=True,
                                                                                 serial_number=serial_number)),
            set(Tag.objects.get(taxonomy__isnull=True, name=name) for name in (tag_name_1, tag_name_2))
        )
        self.assertEqual(
            set(mt.tag for mt in MachineTag.objects.select_related("tag").filter(tag__taxonomy__isnull=False,
                                                                                 serial_number=serial_number)),
            set(Tag.objects.get(taxonomy__name=taxonomy_name_3, name=name) for name in (tag_name_3,))
        )
        # events
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(len(post_event.call_args_list), 3)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_remove_one_tag(self, post_event):
        self._set_required_permission()
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (tag_name_1, tag_name_2) = self._force_machine_tags(serial_number, 2)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self._post_json_data({
                "operations": [{"kind": "REMOVE", "names": [tag_name_1]}],
                "serial_numbers": [serial_number],
            })
        self.assertEqual(
            response.json(),
            {"machines": {"found": 1}, "tags": {"added": 0, "removed": 1}}
        )
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number, tag__name=tag_name_1).count(), 0)
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number, tag__name=tag_name_2).count(), 1)
        # events
        self.assertEqual(len(callbacks), 1)
        event, = [c.args[0] for c in post_event.call_args_list]
        self.assertIsInstance(event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            {'action': 'removed',
             'tag': {'name': tag_name_1, 'pk': Tag.objects.get(name=tag_name_1).pk},
             'taxonomy': {'name': taxonomy_name, 'pk': Taxonomy.objects.get(name=taxonomy_name).pk}}
        )
