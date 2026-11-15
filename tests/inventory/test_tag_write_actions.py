from unittest.mock import patch

from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, Policy, User
from pbac.engine import engine
from pbac.scoping import visible_rows
from pbac.types import SERVICE_ACCOUNT, USER
from tests.munki.utils import force_script_check
from tests.turbo.utils import force_script
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MachineTag, Tag, Taxonomy
from zentral.contrib.inventory.pbac import (TAG_RESOURCE_TYPE, DeleteTagRequest, UpdateTagRequest, ViewTagRequest,
                                            delete_tag_action, update_tag_action,
                                            view_tag_action)


class TagWriteActionsTestCase(TestCase, LoginCase, RequestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                            get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.service_account = User.objects.create(username=get_random_string(12),
                                                  email=f"{get_random_string(12)}@zentral.io",
                                                  is_service_account=True)
        cls.service_account.groups.set([cls.group])
        _, cls.api_key = APIToken.objects.create_for_user(cls.service_account)
        cls.taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        cls.other_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        cls.tag = Tag.objects.create(taxonomy=cls.taxonomy, name=get_random_string(12))
        cls.other_tag = Tag.objects.create(taxonomy=cls.other_taxonomy, name=get_random_string(12))
        cls.root_tag = Tag.objects.create(name=get_random_string(12))

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "inventory"

    # RequestCase implementation

    def _get_api_key(self):
        return self.api_key

    # utility methods

    def _statement(self, effect, action_id, scope="resource", when=""):
        return (f'{effect} (principal in Role::"{self.group.pk}", action == Inventory::Action::"{action_id}", '
                f'{scope}){when};\n')

    def _set_policies(self, *statements, permissions=()):
        self.set_permissions(*permissions)
        if statements:
            Policy.objects.update_or_create(name="Tests tag actions", defaults={"source": "".join(statements)})

    def _in_taxonomy(self, taxonomy):
        return f'resource in Inventory::Taxonomy::"{taxonomy.pk}"'

    def _name_is(self, tag):
        return f' when {{ resource.name == "{tag.name}" }}'

    def _unknown_tag_pk(self):
        tag = Tag.objects.create(name=get_random_string(12))
        pk = tag.pk
        tag.delete()
        return pk

    def _put_tag(self, tag, **kwargs):
        data = {"name": tag.name, "color": tag.color}
        data.update(kwargs)
        return self.put(reverse("inventory_api:tag", args=(tag.pk,)), data)

    def _delete_tag(self, tag):
        return self.delete(reverse("inventory_api:tag", args=(tag.pk,)))

    def _console_update(self, tag, **kwargs):
        data = {"name": tag.name, "color": tag.color}
        if tag.taxonomy_id:
            data["taxonomy"] = tag.taxonomy_id
        data.update(kwargs)
        return self.client.post(reverse("inventory:update_tag", args=(tag.pk,)), data)

    # actions

    def test_view_action(self):
        self.assertEqual(view_tag_action.applies_to.principals, (USER, SERVICE_ACCOUNT))
        self.assertEqual(view_tag_action.applies_to.resources, (TAG_RESOURCE_TYPE,))
        self.assertIsNone(view_tag_action.applies_to.context)
        self.assertEqual(
            [str(group) for group in view_tag_action.parents],
            ['Inventory::Action::"AdminActions"', 'Action::"GlobalAdminActions"',
             'Inventory::Action::"UserActions"', 'Action::"GlobalUserActions"',
             'Inventory::Action::"ViewerActions"', 'Action::"GlobalViewerActions"']
        )
        self.assertNotIn("inventory.view_tag", engine.legacy_perm_actions)
        self._set_policies(self._statement("permit", "viewTag"))
        self.assertFalse(User.objects.get(pk=self.user.pk).has_perm("inventory.view_tag"))

    def test_actions(self):
        for action in (update_tag_action, delete_tag_action):
            self.assertEqual(action.applies_to.principals, (USER, SERVICE_ACCOUNT))
            self.assertEqual(action.applies_to.resources, (TAG_RESOURCE_TYPE,))
            self.assertIsNone(action.applies_to.context)
            self.assertEqual([str(group) for group in action.parents],
                             ['Inventory::Action::"AdminActions"', 'Action::"GlobalAdminActions"'])

    def test_no_legacy_permissions(self):
        self.assertNotIn("inventory.change_tag", engine.legacy_perm_actions)
        self.assertNotIn("inventory.delete_tag", engine.legacy_perm_actions)
        self._set_policies(self._statement("permit", "updateTag"), self._statement("permit", "deleteTag"))
        user = User.objects.get(pk=self.user.pk)
        self.assertFalse(user.has_perm("inventory.change_tag"))
        self.assertFalse(user.has_perm("inventory.delete_tag"))

    def test_request_resources(self):
        for request_class in (ViewTagRequest, UpdateTagRequest, DeleteTagRequest):
            resource = request_class(self.user, self.tag).resource
            self.assertEqual(str(resource), f'Inventory::Tag::"{self.tag.pk}"')
            self.assertEqual([str(parent) for parent in resource.parents],
                             [f'Inventory::Taxonomy::"{self.taxonomy.pk}"'])
            self.assertEqual(request_class(self.user, self.root_tag).resource.parents, [])

    def test_system_any_policy_gives_no_typed_action(self):
        self._set_policies(
            f'permit (principal in Role::"{self.group.pk}", action, resource == System::"any");\n'
        )
        user = User.objects.get(pk=self.user.pk)
        for request_class in (ViewTagRequest, UpdateTagRequest, DeleteTagRequest):
            request = request_class(user, self.root_tag)
            engine.authorize_request(request)
            self.assertFalse(request.is_authorized)

    def test_rows_sql_and_decisions(self):
        # `like` is not in the SQL subset, so each tag gets its own decision: the same rows
        for action_id, request_class in (("viewTag", ViewTagRequest), ("updateTag", UpdateTagRequest),
                                         ("deleteTag", DeleteTagRequest)):
            for forbid in (self._statement("forbid", action_id, self._in_taxonomy(self.other_taxonomy)),
                           self._statement("forbid", action_id, when=self._name_is(self.other_tag)),
                           self._statement("forbid", action_id,
                                           when=f' when {{ resource.name like "{self.other_tag.name}*" }}')):
                self._set_policies(self._statement("permit", action_id), forbid)
                user = User.objects.get(pk=self.user.pk)
                self.assertEqual(
                    set(visible_rows(user, request_class, Tag.objects.all())),
                    {self.tag, self.root_tag}
                )

    # API: update

    def test_api_update_unauthorized(self):
        response = self.put(reverse("inventory_api:tag", args=(self.tag.pk,)), {"name": "yolo"},
                            include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_api_update_no_policy_and_unknown_tag_same_answer(self):
        self._set_policies()
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            refused = self._put_tag(self.tag, name=get_random_string(12))
        self.assertIn(f'Inventory::Action::"updateTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        unknown = self.put(reverse("inventory_api:tag", args=(self._unknown_tag_pk(),)), {"name": "yolo"})
        self.assertEqual(refused.status_code, 404)
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(refused.json(), unknown.json())

    def test_api_update_refused_invalid_body(self):
        self._set_policies(permissions=(view_tag_action,))
        response = self.put(reverse("inventory_api:tag", args=(self.tag.pk,)), {"name": self.other_tag.name})
        self.assertEqual(response.status_code, 404)

    def test_api_update_legacy_policy(self):
        self._set_policies(permissions=(view_tag_action, "inventory.change_taxonomy"))
        self.assertEqual(self._put_tag(self.tag).status_code, 404)

    def test_api_update_the_action_alone(self):
        self._set_policies(self._statement("permit", "updateTag"))
        new_name = get_random_string(12)
        response = self._put_tag(self.tag, name=new_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], new_name)

    def test_api_update_forbid_another_action(self):
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "deleteTag"),
                           self._statement("forbid", "tagAnyMachine"),
                           self._statement("forbid", "createTag"))
        self.assertEqual(self._put_tag(self.tag, name=get_random_string(12)).status_code, 200)

    def test_api_update_forbid_taxonomy(self):
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "updateTag", self._in_taxonomy(self.taxonomy)))
        self.assertEqual(self._put_tag(self.tag, name=get_random_string(12)).status_code, 404)
        self.assertEqual(self._put_tag(self.other_tag, name=get_random_string(12)).status_code, 200)
        self.assertEqual(self._put_tag(self.root_tag, name=get_random_string(12)).status_code, 200)

    def test_api_update_forbid_name(self):
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "updateTag", when=self._name_is(self.tag)))
        self.assertEqual(self._put_tag(self.tag, color="ff0000").status_code, 404)
        self.assertEqual(self._put_tag(self.other_tag, color="ff0000").status_code, 200)

    def test_api_update_in_one_taxonomy_cannot_take_a_tag_of_another(self):
        self._set_policies(self._statement("permit", "updateTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("permit", "createTag",
                                           f'resource == Inventory::Taxonomy::"{self.taxonomy.pk}"'))
        self.assertEqual(self._put_tag(self.other_tag, taxonomy=self.taxonomy.pk).status_code, 404)
        self.assertEqual(self._put_tag(self.root_tag, taxonomy=self.taxonomy.pk).status_code, 404)
        self.other_tag.refresh_from_db()
        self.assertEqual(self.other_tag.taxonomy, self.other_taxonomy)
        self.assertEqual(self._put_tag(self.tag, taxonomy=self.taxonomy.pk, color="ff0000").status_code, 200)

    # API: read

    def _get_tag(self, tag):
        return self.get(reverse("inventory_api:tag", args=(tag.pk,)))

    def _list_tag_pks(self, **params):
        response = self.get(reverse("inventory_api:tags"), params or None)
        self.assertEqual(response.status_code, 200)
        return {tag["id"] for tag in response.json()}

    def test_api_read_unauthorized(self):
        self.assertEqual(self.get(reverse("inventory_api:tags"), include_token=False).status_code, 401)
        response = self.get(reverse("inventory_api:tag", args=(self.tag.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_api_read_no_policy(self):
        self._set_policies()
        self.assertEqual(self._list_tag_pks(), set())
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            refused = self._get_tag(self.tag)
        self.assertIn(f'Inventory::Action::"viewTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        unknown = self.get(reverse("inventory_api:tag", args=(self._unknown_tag_pk(),)))
        self.assertEqual(refused.status_code, 404)
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(refused.json(), unknown.json())

    def test_api_read_legacy_policy(self):
        self._set_policies(permissions=("inventory.view_taxonomy",))
        self.assertEqual(self._list_tag_pks(), set())
        self.assertEqual(self._get_tag(self.tag).status_code, 404)

    def test_api_read_the_action_alone(self):
        self._set_policies(self._statement("permit", "viewTag"),
                           self._statement("forbid", "updateTag"),
                           self._statement("forbid", "deleteTag"),
                           self._statement("forbid", "tagAnyMachine"))
        self.assertEqual(self._list_tag_pks(), {self.tag.pk, self.other_tag.pk, self.root_tag.pk})
        response = self._get_tag(self.tag)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], self.tag.name)
        self.assertEqual(self._put_tag(self.tag, color="ff0000").status_code, 404)
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)

    def test_api_read_in_one_taxonomy(self):
        self._set_policies(self._statement("permit", "viewTag", self._in_taxonomy(self.taxonomy)))
        self.assertEqual(self._list_tag_pks(), {self.tag.pk})
        self.assertEqual(self._get_tag(self.tag).status_code, 200)
        self.assertEqual(self._get_tag(self.other_tag).status_code, 404)
        self.assertEqual(self._get_tag(self.root_tag).status_code, 404)

    def test_api_read_forbid_taxonomy_and_name(self):
        # `like` is not in the SQL subset, so each tag gets its own decision: the same rows
        for name_condition in (f'resource.name == "{self.root_tag.name}"',
                               f'resource.name like "{self.root_tag.name}*"'):
            self._set_policies(self._statement("permit", "viewTag"),
                               self._statement("forbid", "viewTag", self._in_taxonomy(self.taxonomy)),
                               self._statement("forbid", "viewTag", when=f" when {{ {name_condition} }}"))
            self.assertEqual(self._list_tag_pks(), {self.other_tag.pk})
            self.assertEqual(self._get_tag(self.tag).status_code, 404)
            self.assertEqual(self._get_tag(self.root_tag).status_code, 404)
            self.assertEqual(self._get_tag(self.other_tag).status_code, 200)

    def test_api_list_name_filter_hidden_and_unknown_same_answer(self):
        self._set_policies(self._statement("permit", "viewTag", self._in_taxonomy(self.taxonomy)))
        self.assertEqual(self._list_tag_pks(name=self.tag.name), {self.tag.pk})
        self.assertEqual(self._list_tag_pks(name=self.other_tag.name), set())
        self.assertEqual(self._list_tag_pks(name=get_random_string(12)), set())

    def test_api_list_same_number_of_queries(self):
        self._set_policies(self._statement("permit", "viewTag", self._in_taxonomy(self.taxonomy)))
        self._list_tag_pks()
        with CaptureQueriesContext(connection) as ctx:
            self._list_tag_pks()
        for _ in range(3):
            Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        with self.assertNumQueries(len(ctx)):
            self.assertEqual(len(self._list_tag_pks()), 4)

    def test_api_write_action_gives_no_read_endpoint(self):
        self._set_policies(self._statement("permit", "updateTag"), self._statement("permit", "deleteTag"))
        self.assertEqual(self._list_tag_pks(), set())
        self.assertEqual(self._get_tag(self.tag).status_code, 404)
        # the answer of the write shows the tag
        response = self._put_tag(self.tag, color="ff0000")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["name"], self.tag.name)

    # API: delete

    def test_api_delete_unauthorized(self):
        response = self.delete(reverse("inventory_api:tag", args=(self.tag.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_api_delete_no_policy_and_unknown_tag_same_answer(self):
        self._set_policies()
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            refused = self._delete_tag(self.tag)
        self.assertIn(f'Inventory::Action::"deleteTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        unknown = self.delete(reverse("inventory_api:tag", args=(self._unknown_tag_pk(),)))
        self.assertEqual(refused.status_code, 404)
        self.assertEqual(unknown.status_code, 404)
        self.assertEqual(refused.json(), unknown.json())
        self.assertTrue(Tag.objects.filter(pk=self.tag.pk).exists())

    def test_api_delete_legacy_policy(self):
        self._set_policies(permissions=(view_tag_action, "inventory.delete_taxonomy"))
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)

    def test_api_delete_update_tag_is_not_enough(self):
        self._set_policies(self._statement("permit", "updateTag"))
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)

    def test_api_delete_the_action_alone(self):
        self._set_policies(self._statement("permit", "deleteTag"),
                           self._statement("forbid", "updateTag"),
                           self._statement("forbid", "tagAnyMachine"))
        self.assertEqual(self._delete_tag(self.tag).status_code, 204)
        self.assertFalse(Tag.objects.filter(pk=self.tag.pk).exists())

    def test_api_delete_forbid_taxonomy(self):
        self._set_policies(self._statement("permit", "deleteTag"),
                           self._statement("forbid", "deleteTag", self._in_taxonomy(self.taxonomy)))
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)
        self.assertEqual(self._delete_tag(self.other_tag).status_code, 204)
        self.assertEqual(self._delete_tag(self.root_tag).status_code, 204)

    def test_api_delete_forbid_name(self):
        self._set_policies(self._statement("permit", "deleteTag"),
                           self._statement("forbid", "deleteTag", when=self._name_is(self.tag)))
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)
        self.assertEqual(self._delete_tag(self.other_tag).status_code, 204)

    def test_api_delete_used_tag(self):
        self._set_policies(self._statement("permit", "deleteTag"))
        machine_tag = MachineTag.objects.create(serial_number=get_random_string(12), tag=self.tag)
        force_script_check(excluded_tags=[self.other_tag])
        force_script(tag=self.root_tag)
        for tag in (self.tag, self.other_tag, self.root_tag):
            response = self._delete_tag(tag)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), ["This tag cannot be deleted"])
            self.assertTrue(Tag.objects.filter(pk=tag.pk).exists())
        machine_tag.delete()
        self.assertEqual(self._delete_tag(self.tag).status_code, 204)

    def test_api_delete_used_tag_refused(self):
        MachineTag.objects.create(serial_number=get_random_string(12), tag=self.tag)
        self._set_policies(self._statement("permit", "updateTag"))
        self.assertEqual(self._delete_tag(self.tag).status_code, 404)

    def test_links_with_a_relation_without_accessor(self):
        self.assertEqual(self.tag.links(), [])
        self.assertTrue(self.tag.can_be_deleted())
        force_script_check(tags=[self.tag])
        force_script_check(excluded_tags=[self.tag])
        self.assertEqual(sorted(self.tag.links()),
                         [("1 script check", None), ("1 script check, as an excluded tag", None)])
        self.assertFalse(self.tag.can_be_deleted())

    # rename

    def test_api_rename_decided_on_the_new_name(self):
        new_name = get_random_string(12)
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "updateTag", when=f' when {{ resource.name == "{new_name}" }}'))
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._put_tag(self.tag, name=new_name, taxonomy=self.taxonomy.pk)
        self.assertEqual(response.status_code, 403)
        self.assertIn(f'Inventory::Action::"updateTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        self.tag.refresh_from_db()
        self.assertNotEqual(self.tag.name, new_name)
        # another name
        other_name = get_random_string(12)
        self.assertEqual(self._put_tag(self.tag, name=other_name, taxonomy=self.taxonomy.pk).status_code, 200)
        self.tag.refresh_from_db()
        self.assertEqual(self.tag.name, other_name)

    def test_api_same_name_no_second_decision(self):
        self._set_policies(self._statement("permit", "updateTag"))
        with patch("zentral.contrib.inventory.serializers.renamed_tag_request") as renamed_tag_request:
            response = self._put_tag(self.tag, color="ff0000", taxonomy=self.taxonomy.pk)
        self.assertEqual(response.status_code, 200)
        renamed_tag_request.assert_not_called()

    def test_console_rename_decided_on_the_new_name(self):
        new_name = get_random_string(12)
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "updateTag", when=f' when {{ resource.name == "{new_name}" }}'))
        self.client.force_login(self.user)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._console_update(self.tag, name=new_name)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["form"].errors, {"name": ["You cannot give this name to the tag."]})
        self.assertIn(f'Inventory::Action::"updateTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        self.tag.refresh_from_db()
        self.assertNotEqual(self.tag.name, new_name)

    # taxonomy rename: the name is an attribute of the createTag decisions

    def _rename_policies(self, new_name):
        self._set_policies(self._statement("permit", "createTag"),
                           self._statement("forbid", "createTag", when=f' when {{ resource.name == "{new_name}" }}'),
                           permissions=("inventory.change_taxonomy",))

    def test_api_taxonomy_rename_decided_on_the_new_name(self):
        new_name = get_random_string(12)
        self._rename_policies(new_name)
        url = reverse("inventory_api:taxonomy", args=(self.taxonomy.pk,))
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self.put(url, {"name": new_name})
        self.assertEqual(response.status_code, 403)
        self.assertIn(f'Inventory::Action::"createTag" Inventory::Taxonomy::"{self.taxonomy.pk}"', cm.output[0])
        self.taxonomy.refresh_from_db()
        self.assertNotEqual(self.taxonomy.name, new_name)
        # another name
        other_name = get_random_string(12)
        self.assertEqual(self.put(url, {"name": other_name}).status_code, 200)
        self.taxonomy.refresh_from_db()
        self.assertEqual(self.taxonomy.name, other_name)

    def test_api_taxonomy_rename_no_policy(self):
        self._set_policies(permissions=("inventory.change_taxonomy",))
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            response = self.put(reverse("inventory_api:taxonomy", args=(self.taxonomy.pk,)),
                                {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 403)

    def test_api_taxonomy_same_name_no_decision(self):
        self._set_policies(permissions=("inventory.change_taxonomy",))
        with patch("zentral.contrib.inventory.serializers.renamed_taxonomy_request") as renamed_taxonomy_request:
            response = self.put(reverse("inventory_api:taxonomy", args=(self.taxonomy.pk,)),
                                {"name": self.taxonomy.name})
        self.assertEqual(response.status_code, 200)
        renamed_taxonomy_request.assert_not_called()

    def test_console_taxonomy_rename_decided_on_the_new_name(self):
        new_name = get_random_string(12)
        self._rename_policies(new_name)
        self.client.force_login(self.user)
        url = reverse("inventory:update_taxonomy", args=(self.taxonomy.pk,))
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self.client.post(url, {"name": new_name})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["form"].errors, {"name": ["You cannot give this name to the taxonomy."]})
        self.assertIn(f'Inventory::Action::"createTag" Inventory::Taxonomy::"{self.taxonomy.pk}"', cm.output[0])
        self.taxonomy.refresh_from_db()
        self.assertNotEqual(self.taxonomy.name, new_name)
        # another name
        other_name = get_random_string(12)
        self.assertEqual(self.client.post(url, {"name": other_name}).status_code, 302)
        self.taxonomy.refresh_from_db()
        self.assertEqual(self.taxonomy.name, other_name)

    def test_console_taxonomy_same_name_no_decision(self):
        self._set_policies(permissions=("inventory.change_taxonomy",))
        self.client.force_login(self.user)
        with patch("zentral.contrib.inventory.forms.renamed_taxonomy_request") as renamed_taxonomy_request:
            response = self.client.post(reverse("inventory:update_taxonomy", args=(self.taxonomy.pk,)),
                                        {"name": self.taxonomy.name})
        self.assertEqual(response.status_code, 302)
        renamed_taxonomy_request.assert_not_called()

    # delete: the check holds a lock on the row

    def test_delete_check_locks_the_row(self):
        with CaptureQueriesContext(connection) as ctx:
            self.assertTrue(self.root_tag.can_be_deleted(lock=True))
            self.assertFalse(self.taxonomy.can_be_deleted(lock=True))
        self.assertEqual(sum("FOR UPDATE" in query["sql"] for query in ctx.captured_queries), 2)

    # API: taxonomy delete

    def test_api_delete_taxonomy_with_tags(self):
        self._set_policies(self._statement("permit", "deleteTag"), permissions=("inventory.delete_taxonomy",))
        response = self.delete(reverse("inventory_api:taxonomy", args=(self.taxonomy.pk,)))
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), ["This taxonomy cannot be deleted"])
        self.assertTrue(Tag.objects.filter(pk=self.tag.pk).exists())
        self.assertEqual(self._delete_tag(self.tag).status_code, 204)
        response = self.delete(reverse("inventory_api:taxonomy", args=(self.taxonomy.pk,)))
        self.assertEqual(response.status_code, 204)

    # console: index

    def test_index_redirect(self):
        self.login_redirect("tags")

    def test_index_rows(self):
        self._set_policies()
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["tag_list"], [])
        self._set_policies(self._statement("permit", "viewTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("permit", "updateTag"))
        response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(response.context["tag_list"], [self.tag])
        self.assertContains(response, self.tag.name)
        self.assertNotContains(response, self.other_tag.name)
        self.assertNotContains(response, reverse("inventory:update_tag", args=(self.other_tag.pk,)))

    def test_index_controls(self):
        self._set_policies(permissions=(view_tag_action,))
        self.client.force_login(self.user)
        with self.assertNoLogs("zentral.contrib.inventory.views", level="ERROR"):
            response = self.client.get(reverse("inventory:tags"))
        self.assertContains(response, self.tag.name)
        for tag in (self.tag, self.other_tag, self.root_tag):
            self.assertNotContains(response, reverse("inventory:update_tag", args=(tag.pk,)))
            self.assertNotContains(response, reverse("inventory:delete_tag", args=(tag.pk,)))
        self._set_policies(self._statement("permit", "updateTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("permit", "deleteTag", self._in_taxonomy(self.other_taxonomy)),
                           permissions=(view_tag_action,))
        response = self.client.get(reverse("inventory:tags"))
        self.assertContains(response, reverse("inventory:update_tag", args=(self.tag.pk,)))
        self.assertNotContains(response, reverse("inventory:delete_tag", args=(self.tag.pk,)))
        self.assertNotContains(response, reverse("inventory:update_tag", args=(self.other_tag.pk,)))
        self.assertContains(response, reverse("inventory:delete_tag", args=(self.other_tag.pk,)))
        self.assertNotContains(response, reverse("inventory:update_tag", args=(self.root_tag.pk,)))
        self.assertNotContains(response, reverse("inventory:delete_tag", args=(self.root_tag.pk,)))

    def test_index_no_delete_control_for_a_used_tag(self):
        self._set_policies(self._statement("permit", "deleteTag"), permissions=(view_tag_action,))
        MachineTag.objects.create(serial_number=get_random_string(12), tag=self.tag)
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:tags"))
        self.assertNotContains(response, reverse("inventory:delete_tag", args=(self.tag.pk,)))
        self.assertContains(response, reverse("inventory:delete_tag", args=(self.other_tag.pk,)))
        tag = next(tag for tag in response.context["tag_list"] if tag == self.tag)
        self.assertFalse(tag.show_delete_control)
        # the method of the model, not hidden by the control of the page
        self.assertFalse(tag.can_be_deleted())

    def test_index_same_number_of_queries(self):
        self._set_policies(self._statement("permit", "updateTag"), self._statement("permit", "deleteTag"),
                           permissions=(view_tag_action, "inventory.view_taxonomy"))
        self.client.force_login(self.user)
        self.client.get(reverse("inventory:tags"))
        with CaptureQueriesContext(connection) as ctx:
            self.client.get(reverse("inventory:tags"))
        for _ in range(3):
            Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        with self.assertNumQueries(len(ctx)):
            response = self.client.get(reverse("inventory:tags"))
        self.assertEqual(len(response.context["tag_list"]), 6)

    def test_index_taxonomy_delete_control(self):
        empty_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self._set_policies(permissions=(view_tag_action, "inventory.view_taxonomy", "inventory.delete_taxonomy"))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:tags"))
        self.assertContains(response, reverse("inventory:delete_taxonomy", args=(empty_taxonomy.pk,)))
        self.assertNotContains(response, reverse("inventory:delete_taxonomy", args=(self.taxonomy.pk,)))

    # console: update

    def test_console_update_redirect(self):
        self.login_redirect("update_tag", self.tag.pk)

    def test_console_update_no_policy_and_unknown_tag_same_answer(self):
        self._set_policies(permissions=(view_tag_action,))
        self.client.force_login(self.user)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            self.assertEqual(self.client.get(reverse("inventory:update_tag", args=(self.tag.pk,))).status_code, 404)
        self.assertIn(f'Inventory::Action::"updateTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        # not a valid body
        response = self.client.post(reverse("inventory:update_tag", args=(self.tag.pk,)),
                                    {"name": self.other_tag.name})
        self.assertEqual(response.status_code, 404)
        response = self.client.get(reverse("inventory:update_tag", args=(self._unknown_tag_pk(),)))
        self.assertEqual(response.status_code, 404)

    def test_console_update_the_action_alone(self):
        self._set_policies(self._statement("permit", "updateTag"), self._statement("forbid", "deleteTag"))
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("inventory:update_tag", args=(self.tag.pk,))).status_code, 200)
        new_name = get_random_string(12)
        response = self._console_update(self.tag, name=new_name)
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        self.tag.refresh_from_db()
        self.assertEqual(self.tag.name, new_name)

    def test_console_update_forbid_taxonomy_and_name(self):
        self._set_policies(self._statement("permit", "updateTag"),
                           self._statement("forbid", "updateTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("forbid", "updateTag", when=self._name_is(self.root_tag)))
        self.client.force_login(self.user)
        self.assertEqual(self._console_update(self.tag, name=get_random_string(12)).status_code, 404)
        self.assertEqual(self._console_update(self.root_tag, color="ff0000").status_code, 404)
        self.assertEqual(self._console_update(self.other_tag, name=get_random_string(12)).status_code, 302)

    def test_console_update_in_one_taxonomy_cannot_take_a_tag_of_another(self):
        self._set_policies(self._statement("permit", "updateTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("permit", "createTag",
                                           f'resource == Inventory::Taxonomy::"{self.taxonomy.pk}"'))
        self.client.force_login(self.user)
        self.assertEqual(self._console_update(self.other_tag, taxonomy=self.taxonomy.pk).status_code, 404)
        self.other_tag.refresh_from_db()
        self.assertEqual(self.other_tag.taxonomy, self.other_taxonomy)

    # console: delete

    def test_console_delete_redirect(self):
        self.login_redirect("delete_tag", self.tag.pk)

    def test_console_delete_no_policy_and_unknown_tag_same_answer(self):
        self._set_policies(self._statement("permit", "updateTag"), permissions=(view_tag_action,))
        self.client.force_login(self.user)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            self.assertEqual(self.client.get(reverse("inventory:delete_tag", args=(self.tag.pk,))).status_code, 404)
        self.assertIn(f'Inventory::Action::"deleteTag" Inventory::Tag::"{self.tag.pk}"', cm.output[0])
        self.assertEqual(self.client.post(reverse("inventory:delete_tag", args=(self.tag.pk,))).status_code, 404)
        self.assertTrue(Tag.objects.filter(pk=self.tag.pk).exists())
        response = self.client.post(reverse("inventory:delete_tag", args=(self._unknown_tag_pk(),)))
        self.assertEqual(response.status_code, 404)

    def test_console_delete_the_action_alone(self):
        self._set_policies(self._statement("permit", "deleteTag"), self._statement("forbid", "updateTag"))
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("inventory:delete_tag", args=(self.tag.pk,))).status_code, 200)
        response = self.client.post(reverse("inventory:delete_tag", args=(self.tag.pk,)))
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        self.assertFalse(Tag.objects.filter(pk=self.tag.pk).exists())

    def test_console_delete_forbid_taxonomy_and_name(self):
        self._set_policies(self._statement("permit", "deleteTag"),
                           self._statement("forbid", "deleteTag", self._in_taxonomy(self.taxonomy)),
                           self._statement("forbid", "deleteTag", when=self._name_is(self.root_tag)))
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(reverse("inventory:delete_tag", args=(self.tag.pk,))).status_code, 404)
        self.assertEqual(self.client.post(reverse("inventory:delete_tag", args=(self.root_tag.pk,))).status_code,
                         404)
        self.assertEqual(self.client.post(reverse("inventory:delete_tag", args=(self.other_tag.pk,))).status_code,
                         302)

    def test_console_delete_used_tag(self):
        self._set_policies(self._statement("permit", "deleteTag"))
        self.client.force_login(self.user)
        url = reverse("inventory:delete_tag", args=(self.tag.pk,))
        self.assertContains(self.client.get(url), 'class="btn btn-danger"')
        force_script_check(excluded_tags=[self.tag])
        response = self.client.get(url)
        self.assertNotContains(response, 'class="btn btn-danger"')
        self.assertContains(response, "1 script check, as an excluded tag")
        response = self.client.post(url)
        self.assertEqual(response.status_code, 400)
        self.assertTemplateUsed(response, "inventory/tag_confirm_delete.html")
        self.assertTrue(Tag.objects.filter(pk=self.tag.pk).exists())

    # console: taxonomy delete

    def test_console_delete_taxonomy_with_tags(self):
        self._set_policies(self._statement("permit", "deleteTag"), permissions=("inventory.delete_taxonomy",))
        self.client.force_login(self.user)
        url = reverse("inventory:delete_taxonomy", args=(self.taxonomy.pk,))
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(self.client.post(url).status_code, 404)
        self.assertTrue(Tag.objects.filter(pk=self.tag.pk).exists())
        self.tag.delete()
        self.assertRedirects(self.client.post(url), reverse("inventory:tags"), fetch_redirect_response=False)
