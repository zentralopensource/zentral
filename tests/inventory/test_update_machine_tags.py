from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework.authtoken.models import Token
from accounts.models import User
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
        cls.token, _ = Token.objects.get_or_create(user=cls.user)
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
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.user.auth_token.key}"
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
        response = self._post_json_data({"principal_users": {"unique_ids": ["yolo"]}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'tags': ['This field is required.']})

    def test_post_empty_principal_users(self):
        self._set_required_permission()
        response = self._post_json_data({"tags": {"yol": None, "lo": "1"}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'principal_users': ['This field is required.']})

    def test_post_empty_unique_ids_and_principal_names(self):
        self._set_required_permission()
        response = self._post_json_data({"tags": {"yol": None, "lo": "1"}, "principal_users": {}})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'principal_users': {
                 'non_field_errors': ['Unique ids and principal names cannot be both empty.']
             }}
        )

    def test_post_no_change(self):
        self._set_required_permission()
        # non matching machine
        serial_number, _, _ = self._force_machine()
        principal_name = get_random_string(12)
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        response = self._post_json_data({"tags": {taxonomy_name: tag_name},
                                         "principal_users": {"principal_names": [principal_name]}})
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

    def test_post_add_one_tag(self):
        self._set_required_permission()
        # non matching machine
        self._force_machine()
        # matching machine
        serial_number, _, principal_name = self._force_machine()
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        response = self._post_json_data({"tags": {taxonomy_name: tag_name},
                                         "principal_users": {"principal_names": [principal_name]}})
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

    def test_post_add_one_remove_three(self):
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
        response = self._post_json_data({"tags": {taxonomy_name0: tag_names0[0],
                                                  taxonomy_name1: new_taxonomy_tag_name1,
                                                  taxonomy_name2: None},
                                         "principal_users": {"unique_ids": [unique_id]}})
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

    def test_multiple_add_one(self):
        self._set_required_permission()
        # 3 matching machines
        serial_number0, _, principal_name0 = self._force_machine()
        serial_number1, unique_id1, principal_name1 = self._force_machine()
        serial_number2, unique_id2, _ = self._force_machine()
        taxonomy_name = get_random_string(12)
        tag_name = get_random_string(12)
        response = self._post_json_data({"tags": {taxonomy_name: tag_name},
                                         "principal_users": {"unique_ids": [unique_id1, unique_id2],
                                                             "principal_names": [principal_name0, principal_name1]}})
        self.assertEqual(
            response.json(),
            {'machines': {'found': 3}, 'tags': {'added': 3, 'removed': 0}}
        )
        self.assertEqual(
            set(MachineTag.objects.filter(tag__taxonomy__name=taxonomy_name, tag__name=tag_name)
                                  .values_list("serial_number", flat=True)),
            {serial_number0, serial_number1, serial_number2}
        )
