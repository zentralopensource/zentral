from unittest.mock import patch
from django.contrib.auth.models import Group
from django.db import IntegrityError, OperationalError, connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from psycopg2.errors import DeadlockDetected

from accounts.models import APIToken, User
from pbac.engine import engine
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.api_views import UpdateMachineTags
from zentral.contrib.inventory.events import MachineTagEvent
from zentral.contrib.inventory.pbac import locked_rows
from zentral.contrib.inventory.models import (MachineSnapshotCommit, MachineTag, MetaBusinessUnit,
                                              MetaMachine, Tag, Taxonomy, share_lock_rows)


class InventoryAPITests(TestCase, LoginCase, RequestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            "{}@zentral.io".format(get_random_string(12)),
            get_random_string(12)
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.user)
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.service_account.groups.set([cls.group])
        _, cls.service_account_api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.url = reverse("inventory_api:update_machine_tags")

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory_api"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utility methods

    def post(self, data, include_token=True):
        return super().post(self.url, data, include_token)

    def post_as(self, api_key, data):
        return self.client.post(self.url, data, content_type="application/json",
                                HTTP_AUTHORIZATION=f"Token {api_key}")

    def _policy(self, effect, *action_ids, scope="resource", when=None):
        actions = ", ".join(f'Inventory::Action::"{action_id}"' for action_id in action_ids)
        source = f'{effect} (principal in Role::"{self.group.pk}", action in [{actions}], {scope})'
        if when:
            source += f" when {{ {when} }}"
        return source + ";\n"

    def set_required_permission(self, *policies):
        self.set_policy(self._policy("permit", "tagAnyMachine") + "".join(policies))

    def _force_machine(self, business_unit=None):
        serial_number = get_random_string(12)
        unique_id = get_random_string(12)
        principal_name = get_random_string(12)
        tree = {
            "source": {'module': 'io.zentral.tests', 'name': 'zentral'},
            "serial_number": serial_number,
            "principal_user": {
                "source": {"type": "LOGGED_IN_USER", "properties": {"method": "System Configuration"}},
                "unique_id": unique_id,
                "principal_name": principal_name,
                "display_name": get_random_string(12),
            },
        }
        if business_unit:
            tree["business_unit"] = business_unit.serialize()
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
        return serial_number, unique_id, principal_name

    def _events(self, post_event, event_class):
        return [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], event_class)]

    def _force_taxonomy_tag(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        return taxonomy.name, tag.name

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
        response = self.post({}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_post_permission_denied(self):
        # a refused write with a body that is not valid: 403, not 400
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({}, include_token=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            cm.output,
            [f'WARNING:zentral.pbac.utils:Permission denied Request <User::"{self.user.pk}" '
             'Inventory::Action::"tagAnyMachine" ?> Denied']
        )

    def test_post_empty_tags(self):
        self.set_required_permission()
        response = self.post({
            "principal_users": {"unique_ids": ["yolo"]}
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'operations': ['This field is required.']})

    def test_post_principal_users_or_serial_numbers(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "SET", "taxonomy": "yol", "names": []},
                           {"kind": "SET", "taxonomy": "lo", "names": ["1"]}]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'non_field_errors': ['principal_users and serial_numbers cannot be both empty.']}
        )

    def test_post_add_operation_empty_names(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "ADD", "names": []}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'names': ['This list may not be empty for ADD operations']}}}
        )

    def test_post_add_operation_non_empty_taxonomy(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "ADD", "taxonomy": "yol", "names": ["fomo"]}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'taxonomy': ['This field may not be set for ADD operations']}}}
        )

    def test_post_remove_operation_empty_names(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "REMOVE", "names": []}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'names': ['This list may not be empty for REMOVE operations']}}}
        )

    def test_post_set_operation_empty_taxonomy(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "SET", "taxonomy": None, "names": ["yolo"]}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'taxonomy': ['This field is required for SET operations']}}}
        )

    def test_post_remove_operation_non_empty_taxonomy(self):
        self.set_required_permission()
        response = self.post({
            "operations": [{"kind": "REMOVE", "taxonomy": "fomo", "names": ["yolo"]}],
            "serial_numbers": ["un"]
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.json(),
            {'operations': {'0': {'taxonomy': ['This field may not be set for REMOVE operations']}}}
        )

    def test_post_empty_unique_ids_and_principal_names(self):
        self.set_required_permission()
        response = self.post({
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
        self.set_required_permission()
        response = self.post({
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
        self.set_required_permission()
        # non matching machine
        serial_number, _, _ = self._force_machine()
        principal_name = get_random_string(12)
        taxonomy_name, tag_name = self._force_taxonomy_tag()
        response = self.post({
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
        self.set_required_permission()
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        response = self.post({
            "operations": [{"kind": "ADD", "names": [tag.name]}],  # No taxonomy but existing tag with one
            "serial_numbers": [get_random_string(12)],
        })
        self.assertEqual(
            response.json(),
            {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}}
        )

    def test_post_set_tag_outside_the_taxonomy(self):
        # a tag without taxonomy, a tag of another taxonomy, a refused one and an unknown name get the same
        # answer, and the tags outside the taxonomy are not decided
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (tag_name,) = self._force_machine_tags(serial_number, 1)
        tag_without_taxonomy = Tag.objects.create(name=get_random_string(12))
        _, other_taxonomy_tag_name = self._force_taxonomy_tag()
        _, refused_tag_name = self._force_taxonomy_tag()
        self.set_required_permission(
            self._policy("forbid", "tagAnyMachine", when=f'resource.name == "{refused_tag_name}"')
        )
        with self.assertNoLogs("zentral.pbac.utils", "WARNING"):
            response = self.post({"operations": [{"kind": "SET",
                                                  "taxonomy": taxonomy_name,
                                                  "names": [tag_without_taxonomy.name,
                                                            other_taxonomy_tag_name,
                                                            refused_tag_name,
                                                            get_random_string(12)]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {str(i): ["Unknown tag."]
                                                                          for i in range(4)}}}})
        self.assertEqual(
            list(MachineTag.objects.filter(serial_number=serial_number).values_list("tag__name", flat=True)),
            [tag_name]
        )
        # the two permitted tags are not refused
        response = self.post({"operations": [{"kind": "ADD",
                                              "names": [tag_without_taxonomy.name, other_taxonomy_tag_name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 2, 'removed': 0}})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_add_one_tag(self, post_event):
        self.set_required_permission()
        # non matching machine
        self._force_machine()
        # matching machine
        serial_number, _, principal_name = self._force_machine()
        taxonomy_name, tag_name = self._force_taxonomy_tag()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post({
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
        event, = self._events(post_event, MachineTagEvent)
        self.assertEqual(
            event.payload,
            {'action': 'added',
             'tag': {'name': tag_name, 'pk': Tag.objects.get(name=tag_name).pk},
             'taxonomy': {'name': taxonomy_name, 'pk': Taxonomy.objects.get(name=taxonomy_name).pk}}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_add_one_remove_three(self, post_event):
        self.set_required_permission()
        # non matching machine
        self._force_machine()
        # matching machine
        serial_number, unique_id, _ = self._force_machine()
        # 1 taxonomy with 1 tag
        taxonomy_name0, tag_names0 = self._force_machine_tags(serial_number, 1)
        # 1 taxonomy with 2 tags
        taxonomy_name1, _ = self._force_machine_tags(serial_number, 2)
        new_taxonomy_tag_name1 = Tag.objects.create(taxonomy=Taxonomy.objects.get(name=taxonomy_name1),
                                                    name=get_random_string(12)).name
        # 1 taxonomy with 1 tag
        taxonomy_name2, _ = self._force_machine_tags(serial_number, 1)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post({
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
        self.assertEqual(len(self._events(post_event, MachineTagEvent)), 4)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_set_multiple_add_one(self, post_event):
        self.set_required_permission()
        # 3 matching machines
        serial_number0, _, principal_name0 = self._force_machine()
        serial_number1, unique_id1, principal_name1 = self._force_machine()
        serial_number2, unique_id2, _ = self._force_machine()
        taxonomy_name, tag_name = self._force_taxonomy_tag()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post({
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
        self.assertEqual(len(self._events(post_event, MachineTagEvent)), 3)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_add_three_tags(self, post_event):
        self.set_required_permission()
        serial_number, _, principal_name = self._force_machine()
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number).count(), 0)
        tag_name_1 = Tag.objects.create(name=get_random_string(12)).name
        tag_name_2 = Tag.objects.create(name=get_random_string(12)).name
        taxonomy_name_3, tag_name_3 = self._force_taxonomy_tag()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post({
                "operations": [{"kind": "ADD", "names": [tag_name_1, tag_name_2]},
                               {"kind": "ADD", "names": [tag_name_3]}],
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
        self.assertEqual(len(self._events(post_event, MachineTagEvent)), 3)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_remove_one_tag(self, post_event):
        self.set_required_permission()
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (tag_name_1, tag_name_2) = self._force_machine_tags(serial_number, 2)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post({
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

    # PBAC

    def test_post_preview_on_a_tag_name(self):
        # a policy that could permit some tags opens the endpoint, the decisions come after the validation
        self.set_policy(self._policy("permit", "tagAnyMachine", when='resource.name == "yolo"'))
        response = self.post({})
        self.assertEqual(response.status_code, 400)

    def test_post_preview_on_a_taxonomy(self):
        self.set_policy(self._policy("permit", "tagAnyMachine", scope='resource in Inventory::Taxonomy::"1"'))
        response = self.post({})
        self.assertEqual(response.status_code, 400)

    def _unknown_tag_pk(self):
        return Tag.objects.order_by("-pk").values_list("pk", flat=True).first() + 1000

    def _patch_update_machine_tags(self, first_attempt):
        # first_attempt runs before the first call of the first attempt, in the savepoint of the attempt
        update_machine_tags = UpdateMachineTags._update_machine_tags
        calls = []

        def side_effect(view, serial_number):
            calls.append(serial_number)
            if len(calls) == 1:
                first_attempt(serial_number)
            return update_machine_tags(view, serial_number)

        return patch.object(UpdateMachineTags, "_update_machine_tags", autospec=True, side_effect=side_effect)

    def _insert_machine_tag_with_unknown_tag(self, serial_number):
        # a machine tag of a tag that another request deleted: the deferred foreign key fails at the check
        with connection.cursor() as cursor:
            cursor.execute("insert into inventory_machinetag(serial_number, tag_id) values (%s, %s)",
                           [serial_number, self._unknown_tag_pk()])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_runs_again_after_a_foreign_key_error(self, post_event):
        tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission()
        with self._patch_update_machine_tags(self._insert_machine_tag_with_unknown_tag):
            with self.assertLogs("zentral.contrib.inventory.api_views", "WARNING") as cm:
                with self.captureOnCommitCallbacks(execute=True):
                    response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                                          "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}})
        self.assertEqual(len(cm.output), 1)
        self.assertIn("Mass tagging attempt 1 failed", cm.output[0])
        self.assertEqual(
            list(MachineTag.objects.filter(serial_number=serial_number).values_list("tag", flat=True)),
            [tag.pk]
        )
        # no event for the first attempt
        event, = self._events(post_event, MachineTagEvent)
        self.assertEqual(event.payload["action"], "added")

    def test_post_tag_deleted_before_the_second_attempt(self):
        # the second attempt reads the tags again: a deleted tag gets the answer of an unknown tag
        tag = Tag.objects.create(name=get_random_string(12))
        other_tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission()
        resolve_tags = UpdateMachineTags._resolve_tags
        resolve_calls = []

        def delete_then_resolve(view):
            resolve_calls.append(1)
            if len(resolve_calls) == 2:
                Tag.objects.filter(pk=tag.pk).delete()
            return resolve_tags(view)

        with self._patch_update_machine_tags(self._insert_machine_tag_with_unknown_tag):
            with patch.object(UpdateMachineTags, "_resolve_tags", autospec=True, side_effect=delete_then_resolve):
                with self.assertLogs("zentral.contrib.inventory.api_views", "WARNING"):
                    response = self.post({"operations": [{"kind": "ADD", "names": [tag.name, other_tag.name]}],
                                          "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {"0": ["Unknown tag."]}}}})
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_runs_again_after_a_deadlock(self):
        tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission()

        def deadlock(serial_number):
            try:
                raise DeadlockDetected("deadlock detected")
            except DeadlockDetected as e:
                raise OperationalError(str(e)) from e

        with self._patch_update_machine_tags(deadlock):
            with self.assertLogs("zentral.contrib.inventory.api_views", "WARNING"):
                response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                                      "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_post_other_operational_error_not_run_again(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_required_permission()
        with patch.object(UpdateMachineTags, "_update_machine_tags", side_effect=OperationalError("yolo")) as update:
            with self.assertRaises(OperationalError):
                self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                           "serial_numbers": [get_random_string(12)]})
        update.assert_called_once()

    def test_post_three_attempts(self):
        tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission()
        update_machine_tags = UpdateMachineTags._update_machine_tags

        def always_unknown_tag(view, serial_number):
            self._insert_machine_tag_with_unknown_tag(serial_number)
            return update_machine_tags(view, serial_number)

        with patch.object(UpdateMachineTags, "_update_machine_tags", autospec=True,
                          side_effect=always_unknown_tag) as update:
            with self.assertLogs("zentral.contrib.inventory.api_views", "WARNING") as cm:
                with self.assertRaises(IntegrityError):
                    self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                               "serial_numbers": [serial_number]})
        self.assertEqual(update.call_count, 3)
        self.assertEqual(len(cm.output), 2)

    def test_post_add_unknown_or_refused_tag(self):
        # a refused tag gets the answer of an unknown tag, and no tag is created
        tag = Tag.objects.create(name=get_random_string(12))
        refused_tag = Tag.objects.create(name=get_random_string(12))
        unknown_tag_name = get_random_string(12)
        serial_number = get_random_string(12)
        self.set_required_permission(
            self._policy("forbid", "tagAnyMachine", when=f'resource.name == "{refused_tag.name}"')
        )
        expected_response = {"operations": {"0": {"names": {"1": ["Unknown tag."]}}}}
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({"operations": [{"kind": "ADD", "names": [tag.name, refused_tag.name]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{refused_tag.pk}"> Denied', cm.output[0])
        response = self.post({"operations": [{"kind": "ADD", "names": [tag.name, unknown_tag_name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertFalse(Tag.objects.filter(name=unknown_tag_name).exists())
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    # the decisions are on the rows read again under a share lock

    def test_post_locks_the_rows(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        set_tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=Taxonomy.objects.create(name=get_random_string(12)),
                                 name=get_random_string(12))
        self.set_required_permission()
        with CaptureQueriesContext(connection) as ctx:
            response = self.post({"operations": [{"kind": "SET", "taxonomy": taxonomy.name, "names": [set_tag.name]},
                                                 {"kind": "ADD", "names": [tag.name]}],
                                  "serial_numbers": [get_random_string(12)]})
        self.assertEqual(response.status_code, 200)
        lock_queries = [query["sql"] for query in ctx.captured_queries if query["sql"].endswith(" FOR SHARE")]
        self.assertEqual([query.split(" FROM ")[1].split(" ")[0] for query in lock_queries],
                         ['"inventory_taxonomy"', '"inventory_tag"', '"inventory_taxonomy"'])

    def test_post_decides_on_the_current_row(self):
        # a move of the tag to a refused taxonomy commits between the first read and the lock
        tag = Tag.objects.create(name=get_random_string(12))
        refused_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission(
            self._policy("forbid", "tagAnyMachine", scope=f'resource in Inventory::Taxonomy::"{refused_taxonomy.pk}"')
        )

        def move_then_lock(*args, **kwargs):
            Tag.objects.filter(pk=tag.pk).update(taxonomy=refused_taxonomy)
            return locked_rows(*args, **kwargs)

        with patch("zentral.contrib.inventory.api_views.locked_rows", side_effect=move_then_lock):
            with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
                response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                                      "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {"0": ["Unknown tag."]}}}})
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{tag.pk}"> Denied', cm.output[0])
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_tag_renamed_before_the_lock(self):
        # a rename commits between the first read and the lock: the tag is not the one that the operation names
        tag = Tag.objects.create(name=get_random_string(12))
        new_name = get_random_string(12)
        serial_number = get_random_string(12)
        self.set_required_permission(self._policy("forbid", "tagAnyMachine", when=f'resource.name == "{new_name}"'))

        def rename_then_lock(model, pks):
            pks = list(pks)
            if model is Tag:
                Tag.objects.filter(pk=tag.pk).update(name=new_name)
            return share_lock_rows(model, pks)

        # the renamed tag is not decided
        with patch("zentral.contrib.inventory.pbac.share_lock_rows", side_effect=rename_then_lock), \
             self.assertNoLogs("zentral.pbac.utils"):
            response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {"0": ["Unknown tag."]}}}})
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_add_forbid_on_other_actions(self):
        tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission(self._policy("forbid", "createMachineTag", "deleteMachineTag"))
        response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_post_add_forbid_on_taxonomy(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        other_tag = Tag.objects.create(name=get_random_string(12))
        serial_number = get_random_string(12)
        self.set_required_permission(
            self._policy("forbid", "tagAnyMachine", scope=f'resource in Inventory::Taxonomy::"{taxonomy.pk}"')
        )
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({"operations": [{"kind": "ADD", "names": [other_tag.name, tag.name]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {"1": ["Unknown tag."]}}}})
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{tag.pk}"> Denied', cm.output[0])
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())
        # the other tag
        response = self.post({"operations": [{"kind": "ADD", "names": [other_tag.name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=other_tag).exists())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_post_two_sets_on_one_taxonomy(self, post_event):
        # the two operations give their tags, and only the other tags of the taxonomy are removed
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (tag_name_1, tag_name_2, tag_name_3) = self._force_machine_tags(serial_number, 3)
        self.set_required_permission()
        with patch.object(engine, "authorize_requests", wraps=engine.authorize_requests) as authorize_requests:
            with self.captureOnCommitCallbacks(execute=True):
                response = self.post({"operations": [{"kind": "SET", "taxonomy": taxonomy_name,
                                                      "names": [tag_name_1]},
                                                     {"kind": "SET", "taxonomy": taxonomy_name,
                                                      "names": [tag_name_2]}],
                                      "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 0, 'removed': 1}})
        self.assertEqual(
            set(MachineTag.objects.filter(serial_number=serial_number).values_list("tag__name", flat=True)),
            {tag_name_1, tag_name_2}
        )
        event, = self._events(post_event, MachineTagEvent)
        self.assertEqual(event.payload["action"], "removed")
        self.assertEqual(event.payload["tag"]["name"], tag_name_3)
        # one decision for each tag
        self.assertEqual(len(authorize_requests.call_args.args[0]), 3)

    def test_post_set_unknown_tag_or_taxonomy(self):
        # nothing is created
        serial_number, _, _ = self._force_machine()
        taxonomy_name, tag_name = self._force_taxonomy_tag()
        unknown_name = get_random_string(12)
        self.set_required_permission()
        response = self.post({"operations": [{"kind": "SET", "taxonomy": taxonomy_name, "names": [unknown_name]},
                                             {"kind": "SET", "taxonomy": unknown_name, "names": [tag_name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"names": {"0": ["Unknown tag."]}},
                                                          "1": {"names": {"0": ["Unknown tag."]},
                                                                "taxonomy": ["Unknown taxonomy."]}}})
        self.assertFalse(Tag.objects.filter(name=unknown_name).exists())
        self.assertFalse(Taxonomy.objects.filter(name=unknown_name).exists())
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_set_forbid_on_a_removed_tag(self):
        # a SET operation removes the other tags of its taxonomy: it decides on each of them, and a taxonomy with
        # a refused tag gets the answer of an unknown taxonomy
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (kept_tag_name, removed_tag_name) = self._force_machine_tags(serial_number, 2)
        removed_tag = Tag.objects.get(name=removed_tag_name)
        self.set_required_permission(
            self._policy("forbid", "tagAnyMachine", scope=f'resource == Inventory::Tag::"{removed_tag.pk}"')
        )
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({"operations": [{"kind": "SET", "taxonomy": taxonomy_name,
                                                  "names": [kept_tag_name]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"operations": {"0": {"taxonomy": ["Unknown taxonomy."]}}})
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{removed_tag.pk}"> Denied', cm.output[0])
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number).count(), 2)

    def test_post_remove(self):
        serial_number, _, _ = self._force_machine()
        _, (tag_name,) = self._force_machine_tags(serial_number, 1)
        self.set_policy(self._policy("permit", "tagAnyMachine"))
        response = self.post({"operations": [{"kind": "REMOVE", "names": [tag_name]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 0, 'removed': 1}})
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_remove_unknown_or_refused_tag(self):
        # a refused tag gets the answer of an unknown tag
        serial_number, _, _ = self._force_machine()
        _, (tag_name, refused_tag_name) = self._force_machine_tags(serial_number, 2)
        self.set_policy(self._policy("permit", "tagAnyMachine")
                        + self._policy("forbid", "tagAnyMachine", when=f'resource.name == "{refused_tag_name}"'))
        expected_response = {"operations": {"0": {"names": {"1": ["Unknown tag."]}}}}
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({"operations": [{"kind": "REMOVE", "names": [tag_name, refused_tag_name]}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertEqual(len(cm.output), 1)
        self.assertIn('Inventory::Action::"tagAnyMachine" Inventory::Tag::', cm.output[0])
        response = self.post({"operations": [{"kind": "REMOVE", "names": [tag_name, get_random_string(12)]}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number).count(), 2)

    def test_post_clear_unknown_or_refused_taxonomy(self):
        # a taxonomy with a refused tag gets the answer of an unknown taxonomy
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (_, refused_tag_name) = self._force_machine_tags(serial_number, 2)
        refused_tag = Tag.objects.get(name=refused_tag_name)
        self.set_policy(
            self._policy("permit", "tagAnyMachine")
            + self._policy("forbid", "tagAnyMachine", scope=f'resource == Inventory::Tag::"{refused_tag.pk}"')
        )
        expected_response = {"operations": {"1": {"taxonomy": ["Unknown taxonomy."]}}}
        tag = Tag.objects.create(name=get_random_string(12))
        operations = [{"kind": "REMOVE", "names": [tag.name]}]
        with self.assertLogs("zentral.pbac.utils", "WARNING") as cm:
            response = self.post({"operations": operations + [{"kind": "SET", "taxonomy": taxonomy_name, "names": []}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{refused_tag.pk}"> Denied', cm.output[0])
        response = self.post({"operations": operations + [{"kind": "SET", "taxonomy": get_random_string(12),
                                                           "names": []}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), expected_response)
        self.assertEqual(MachineTag.objects.filter(serial_number=serial_number).count(), 2)

    def test_post_set_taxonomy_without_tags(self):
        # a SET operation on a taxonomy without tags gets the answer of an unknown taxonomy, so that a role that
        # no tag permits never gets the number of machines of a principal user
        _, _, principal_name = self._force_machine()
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_policy(self._policy("permit", "tagAnyMachine",
                                     scope='resource in Inventory::MetaBusinessUnit::"1"'))
        for name in (taxonomy.name, get_random_string(12)):
            response = self.post({"operations": [{"kind": "SET", "taxonomy": name, "names": []}],
                                  "principal_users": {"principal_names": [principal_name]}})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"operations": {"0": {"taxonomy": ["Unknown taxonomy."]}}})

    def test_post_clear(self):
        serial_number, _, _ = self._force_machine()
        taxonomy_name, _ = self._force_machine_tags(serial_number, 2)
        self.set_policy(self._policy("permit", "tagAnyMachine"))
        response = self.post({"operations": [{"kind": "SET", "taxonomy": taxonomy_name, "names": []}],
                              "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 0, 'removed': 2}})
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number).exists())

    def test_post_same_answer_for_every_serial_number(self):
        # the resource is the tag: a policy scoped to machines never limits this endpoint
        meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        enrolled_serial_number, _, _ = self._force_machine(meta_business_unit.create_enrollment_business_unit())
        tag = Tag.objects.create(name=get_random_string(12))
        self.set_required_permission(self._policy(
            "forbid", "tagAnyMachine", "createMachineTag", "deleteMachineTag",
            scope=f'resource in Inventory::MetaBusinessUnit::"{meta_business_unit.pk}"'
        ))
        for serial_number in (enrolled_serial_number, get_random_string(12)):
            response = self.post({"operations": [{"kind": "ADD", "names": [tag.name]}],
                                  "serial_numbers": [serial_number]})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 1, 'removed': 0}})
            self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())

    def test_post_decides_once(self):
        # one decision for each tag, in one batch
        serial_number, _, _ = self._force_machine()
        taxonomy_name, (tag_name,) = self._force_machine_tags(serial_number, 1)
        other_taxonomy_name, (other_tag_name,) = self._force_machine_tags(serial_number, 1)
        self.set_required_permission()
        with patch.object(engine, "authorize_requests", wraps=engine.authorize_requests) as authorize_requests:
            response = self.post({"operations": [{"kind": "ADD", "names": [tag_name]},
                                                 {"kind": "SET", "taxonomy": taxonomy_name, "names": [tag_name]},
                                                 {"kind": "REMOVE", "names": [other_tag_name]},
                                                 {"kind": "REMOVE", "names": [other_tag_name]},
                                                 {"kind": "SET", "taxonomy": other_taxonomy_name, "names": []}],
                                  "serial_numbers": [serial_number]})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'machines': {'found': 1}, 'tags': {'added': 0, 'removed': 1}})
        authorize_requests.assert_called_once()
        tag = Tag.objects.get(name=tag_name)
        other_tag = Tag.objects.get(name=other_tag_name)
        self.assertCountEqual(
            [(r.action.id, str(r.resource)) for r in authorize_requests.call_args.args[0]],
            [("tagAnyMachine", f'Inventory::Tag::"{tag.pk}"'),
             ("tagAnyMachine", f'Inventory::Tag::"{other_tag.pk}"')]
        )

    def test_post_fence_on_a_tag(self):
        # A forbid on createMachineTag with the tag name in the context applied to the tags page only. This
        # endpoint decided the add_machinetag legacy perm on System::"any", with no context, so no forbid could
        # fence a tag on it. It decides tagAnyMachine on the tag, for a user and a service account.
        self.assertNotIn("inventory.add_machinetag", engine.legacy_perm_actions)
        self.assertNotIn("inventory.delete_machinetag", engine.legacy_perm_actions)
        serial_number, _, _ = self._force_machine()
        tag = Tag.objects.create(name=get_random_string(12))
        other_tag = Tag.objects.create(name=get_random_string(12))
        self.set_policy(
            self._policy("permit", "AdminActions")
            + self._policy("forbid", "createMachineTag", "deleteMachineTag",
                           when=f'context has tagID && context.tagID == {tag.pk}')
            + self._policy("forbid", "tagAnyMachine", scope=f'resource == Inventory::Tag::"{tag.pk}"')
        )
        for api_key in (self.api_key, self.service_account_api_key):
            for kind in ("ADD", "REMOVE"):
                with self.assertLogs("zentral.pbac.utils", "WARNING"):
                    response = self.post_as(api_key, {"operations": [{"kind": kind, "names": [tag.name]}],
                                                      "serial_numbers": [serial_number]})
                self.assertEqual(response.status_code, 400)
            response = self.post_as(api_key, {"operations": [{"kind": "ADD", "names": [other_tag.name]}],
                                              "serial_numbers": [serial_number]})
            self.assertEqual(response.status_code, 200)
        self.assertFalse(MachineTag.objects.filter(serial_number=serial_number, tag=tag).exists())
        self.assertTrue(MachineTag.objects.filter(serial_number=serial_number, tag=other_tag).exists())
        # the same fence on the tags page
        self.client.force_login(self.user)
        urlsafe_serial_number = MetaMachine(serial_number).get_urlsafe_serial_number()
        response = self.client.post(reverse("inventory:create_machine_tag", args=(urlsafe_serial_number, tag.pk)))
        self.assertEqual(response.status_code, 404)
        response = self.client.post(reverse("inventory:delete_machine_tag",
                                            args=(urlsafe_serial_number, other_tag.pk)))
        self.assertEqual(response.status_code, 302)
