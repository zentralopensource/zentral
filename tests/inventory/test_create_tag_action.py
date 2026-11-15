from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, Policy, User
from pbac.engine import engine
from pbac.types import SERVICE_ACCOUNT, SYSTEM, USER
from tests.zentral_test_utils.choices import offered
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag, Taxonomy
from zentral.contrib.inventory.pbac import (TAXONOMY_RESOURCE_TYPE, CreateTagRequest, create_tag_action,
                                            taxonomies_for_create_tag, taxonomies_for_tag_creation_later,
                                            update_tag_action,
                                            view_tag_action)


class CreateTagActionTestCase(TestCase, LoginCase, RequestCase):
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
        return f'resource == Inventory::Taxonomy::"{taxonomy.pk}"'

    def _unknown_taxonomy_pk(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        pk = taxonomy.pk
        taxonomy.delete()
        return pk

    def _post_tag(self, taxonomy=None, name=None, **kwargs):
        data = {"name": name or get_random_string(12), "color": "ff0000"}
        if taxonomy is not None:
            data["taxonomy"] = taxonomy.pk if isinstance(taxonomy, Taxonomy) else taxonomy
        data.update(kwargs)
        return self.post(reverse("inventory_api:tags"), data)

    def _put_tag(self, tag, **kwargs):
        data = {"name": tag.name, "color": tag.color}
        data.update(kwargs)
        return self.put(reverse("inventory_api:tag", args=(tag.pk,)), data)

    # action

    def test_action(self):
        self.assertEqual(create_tag_action.applies_to.principals, (USER, SERVICE_ACCOUNT))
        self.assertEqual(create_tag_action.applies_to.resources, (TAXONOMY_RESOURCE_TYPE, SYSTEM))
        self.assertIsNone(create_tag_action.applies_to.context)
        self.assertEqual([str(group) for group in create_tag_action.parents],
                         ['Inventory::Action::"AdminActions"', 'Action::"GlobalAdminActions"'])

    def test_no_legacy_permission(self):
        self.assertNotIn("inventory.add_tag", engine.legacy_perm_actions)
        self._set_policies(self._statement("permit", "createTag"))
        self.assertFalse(User.objects.get(pk=self.user.pk).has_perm("inventory.add_tag"))

    def test_request_resources(self):
        self.assertEqual(str(CreateTagRequest(self.user, None).resource), 'System::"root"')
        self.assertEqual(str(CreateTagRequest(self.user, self.taxonomy).resource),
                         f'Inventory::Taxonomy::"{self.taxonomy.pk}"')
        self.assertIsNot(engine.system_root_resource, engine.system_any_resource)
        self.assertEqual(str(engine.system_any_resource), 'System::"any"')

    def test_system_root_policy_gives_no_legacy_permission(self):
        self._set_policies(
            f'permit (principal in Role::"{self.group.pk}", action, resource == System::"root");\n'
        )
        user = User.objects.get(pk=self.user.pk)
        self.assertFalse(user.has_perm("inventory.view_taxonomy"))
        request = CreateTagRequest(user, None)
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_system_any_policy_gives_no_typed_action(self):
        self._set_policies(
            f'permit (principal in Role::"{self.group.pk}", action, resource == System::"any");\n'
        )
        user = User.objects.get(pk=self.user.pk)
        self.assertTrue(user.has_perm("inventory.view_taxonomy"))
        for taxonomy in (None, self.taxonomy):
            request = CreateTagRequest(user, taxonomy)
            engine.authorize_request(request)
            self.assertFalse(request.is_authorized)

    def test_taxonomies_for_create_tag_sql_and_decisions(self):
        # `like` is not in the SQL subset, so each taxonomy gets its own decision: the same rows
        for forbid in (self._statement("forbid", "createTag", self._in_taxonomy(self.other_taxonomy)),
                       self._statement("forbid", "createTag",
                                       when=f' when {{ resource.name == "{self.other_taxonomy.name}" }}'),
                       self._statement("forbid", "createTag",
                                       when=f' when {{ resource.name like "{self.other_taxonomy.name}*" }}')):
            self._set_policies(self._statement("permit", "createTag"), forbid)
            user = User.objects.get(pk=self.user.pk)
            self.assertEqual(list(taxonomies_for_create_tag(user)), [self.taxonomy])

    def test_taxonomies_for_tag_creation_later(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        Tag.objects.create(name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag"), self._statement("permit", "tagAnyMachine"),
                           self._statement("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{tag.pk}"'))
        user = User.objects.get(pk=self.user.pk)
        self.assertEqual(list(taxonomies_for_tag_creation_later(user)), [self.other_taxonomy])

    # API: create

    def test_api_create_unauthorized(self):
        response = self.post(reverse("inventory_api:tags"), {"name": get_random_string(12)}, include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_api_create_no_policy(self):
        self._set_policies()
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._post_tag(self.taxonomy)
        self.assertEqual(response.status_code, 403)
        self.assertIn('Inventory::Action::"createTag" ?> Denied', cm.output[0])

    def test_api_create_no_policy_invalid_body(self):
        self._set_policies()
        response = self.post(reverse("inventory_api:tags"), {"taxonomy": "yolo"})
        self.assertEqual(response.status_code, 403)

    def test_api_create_legacy_policy(self):
        # a policy with no condition on the resource, as the policies made from the legacy roles
        self._set_policies(self._statement("permit", "createTag"))
        self.assertEqual(self._post_tag(self.taxonomy).status_code, 201)
        self.assertEqual(self._post_tag().status_code, 201)
        self.assertEqual(self._post_tag(taxonomy=None, meta_business_unit=None).status_code, 201)

    def test_api_create_forbid_another_action(self):
        self._set_policies(self._statement("permit", "createTag"), self._statement("forbid", "tagAnyMachine"),
                           self._statement("forbid", "updateTag"))
        response = self._post_tag(self.taxonomy)
        self.assertEqual(response.status_code, 201)
        self.assertEqual(Tag.objects.get(pk=response.json()["id"]).taxonomy, self.taxonomy)

    def test_api_create_in_one_taxonomy(self):
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)))
        self.assertEqual(self._post_tag(self.taxonomy).status_code, 201)
        # the answer of an unknown taxonomy
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._post_tag(self.other_taxonomy)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"taxonomy": [f'Invalid pk "{self.other_taxonomy.pk}" - object does not exist.']})
        self.assertIn(f'Inventory::Action::"createTag" Inventory::Taxonomy::"{self.other_taxonomy.pk}"',
                      cm.output[0])
        unknown_pk = self._unknown_taxonomy_pk()
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self._post_tag(unknown_pk)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"taxonomy": [f'Invalid pk "{unknown_pk}" - object does not exist.']})
        # no taxonomy: System::"root"
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._post_tag()
        self.assertEqual(response.status_code, 403)
        self.assertIn('Inventory::Action::"createTag" System::"root"', cm.output[0])

    def test_api_create_refused_and_unknown_taxonomy_same_errors(self):
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)))
        tag = Tag.objects.create(name=get_random_string(12))
        unknown_pk = self._unknown_taxonomy_pk()
        responses = [self._post_tag(pk, name=tag.name, color="zzz").json()
                     for pk in (self.other_taxonomy.pk, unknown_pk)]
        self.assertEqual(set(responses[0]), {"taxonomy", "name", "color"})
        self.assertEqual(responses[0]["name"], responses[1]["name"])
        self.assertEqual(responses[0]["color"], responses[1]["color"])
        self.assertEqual(responses[0]["taxonomy"][0].replace(str(self.other_taxonomy.pk), "X"),
                         responses[1]["taxonomy"][0].replace(str(unknown_pk), "X"))

    def test_api_create_taxonomy_wrong_type(self):
        self._set_policies(self._statement("permit", "createTag"))
        for value in ("yolo", True, [1]):
            with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
                response = self._post_tag(value)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(list(response.json()), ["taxonomy"])

    def test_api_create_body_not_an_object(self):
        self._set_policies(self._statement("permit", "createTag"))
        response = self.post(reverse("inventory_api:tags"), [1, 2])
        self.assertEqual(response.status_code, 400)

    def test_api_create_forbid_taxonomy_name(self):
        self._set_policies(
            self._statement("permit", "createTag"),
            self._statement("forbid", "createTag", when=f' when {{ resource.name == "{self.taxonomy.name}" }}'),
        )
        self.assertEqual(self._post_tag(self.taxonomy).status_code, 400)
        self.assertEqual(self._post_tag(self.other_taxonomy).status_code, 201)

    def test_api_create_on_root_only(self):
        self._set_policies(self._statement("permit", "createTag", 'resource == System::"root"'))
        self.assertEqual(self._post_tag().status_code, 201)
        self.assertEqual(self._post_tag(self.taxonomy).status_code, 400)

    def test_api_create_root_refused_invalid_body(self):
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)))
        response = self.post(reverse("inventory_api:tags"), {"color": "zzz"})
        self.assertEqual(response.status_code, 403)

    def test_api_list_needs_the_view_action(self):
        Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag"))
        response = self.get(reverse("inventory_api:tags"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])
        self._set_policies(permissions=(view_tag_action,))
        self.assertEqual(len(self.get(reverse("inventory_api:tags")).json()), 1)

    # API: update

    def test_api_update_same_taxonomy_without_create_tag(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(permissions=(update_tag_action,))
        new_name = get_random_string(12)
        response = self._put_tag(tag, taxonomy=self.taxonomy.pk, name=new_name)
        self.assertEqual(response.status_code, 200)
        tag.refresh_from_db()
        self.assertEqual(tag.name, new_name)
        # the taxonomy is not in the body: no change
        self.assertEqual(self._put_tag(tag).status_code, 200)
        tag.refresh_from_db()
        self.assertEqual(tag.taxonomy, self.taxonomy)

    def test_api_update_no_taxonomy_without_create_tag(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._set_policies(permissions=(update_tag_action,))
        self.assertEqual(self._put_tag(tag, taxonomy=None).status_code, 200)

    def test_api_update_new_taxonomy_without_create_tag(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(permissions=(update_tag_action,))
        response = self._put_tag(tag, taxonomy=self.other_taxonomy.pk)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(),
                         {"taxonomy": [f'Invalid pk "{self.other_taxonomy.pk}" - object does not exist.']})
        tag.refresh_from_db()
        self.assertEqual(tag.taxonomy, self.taxonomy)

    def test_api_update_new_taxonomy(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.other_taxonomy)),
                           permissions=(update_tag_action,))
        self.assertEqual(self._put_tag(tag, taxonomy=self.other_taxonomy.pk).status_code, 200)
        tag.refresh_from_db()
        self.assertEqual(tag.taxonomy, self.other_taxonomy)

    def test_api_update_to_no_taxonomy(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.other_taxonomy)),
                           permissions=(update_tag_action,))
        self.assertEqual(self._put_tag(tag, taxonomy=None).status_code, 403)
        tag.refresh_from_db()
        self.assertEqual(tag.taxonomy, self.taxonomy)
        self._set_policies(self._statement("permit", "createTag", 'resource == System::"root"'),
                           permissions=(update_tag_action,))
        self.assertEqual(self._put_tag(tag, taxonomy=None).status_code, 200)
        tag.refresh_from_db()
        self.assertIsNone(tag.taxonomy)

    def test_api_update_create_tag_alone(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag"))
        self.assertEqual(self._put_tag(tag, taxonomy=self.other_taxonomy.pk).status_code, 404)

    # console: index

    def test_index_create_button(self):
        self._set_policies(permissions=(view_tag_action,))
        self.client.force_login(self.user)
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.client.get(reverse("inventory:tags"))
        self.assertNotContains(response, reverse("inventory:create_tag"))
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)),
                           permissions=(view_tag_action,))
        response = self.client.get(reverse("inventory:tags"))
        self.assertContains(response, reverse("inventory:create_tag"))

    # console: create

    def test_console_create_redirect(self):
        self.login_redirect("create_tag")

    def test_console_create_no_policy(self):
        self._set_policies(permissions=(view_tag_action, update_tag_action))
        self.client.force_login(self.user)
        with self.assertLogs("zentral.pbac.utils", level="WARNING"):
            self.assertEqual(self.client.get(reverse("inventory:create_tag")).status_code, 403)
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": get_random_string(12), "color": "ff0000"})
        self.assertEqual(response.status_code, 403)

    def test_console_create_in_one_taxonomy(self):
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:create_tag"))
        self.assertEqual(response.status_code, 200)
        field = response.context["form"].fields["taxonomy"]
        self.assertEqual(offered(field), [self.taxonomy])
        self.assertIsNone(field.empty_label)
        # a refused taxonomy and an unknown one: not a valid choice
        for pk in (self.other_taxonomy.pk, self._unknown_taxonomy_pk()):
            response = self.client.post(reverse("inventory:create_tag"),
                                        {"name": get_random_string(12), "color": "ff0000", "taxonomy": pk})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response.context["form"].errors,
                {"taxonomy": ["Select a valid choice. That choice is not one of the available choices."]}
            )
        # no taxonomy
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": get_random_string(12), "color": "ff0000"})
        self.assertEqual(response.context["form"].errors, {"taxonomy": ["This field is required."]})
        name = get_random_string(12)
        response = self.client.post(reverse("inventory:create_tag"),
                                    {"name": name, "color": "ff0000", "taxonomy": self.taxonomy.pk})
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        self.assertEqual(Tag.objects.get(name=name).taxonomy, self.taxonomy)

    def test_console_create_refusals_logged(self):
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.taxonomy)))
        self.client.force_login(self.user)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            self.client.post(reverse("inventory:create_tag"),
                             {"name": get_random_string(12), "color": "ff0000", "taxonomy": self.other_taxonomy.pk})
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"createTag" Inventory::Taxonomy::"{self.other_taxonomy.pk}"',
                      cm.output[0])
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            self.client.post(reverse("inventory:create_tag"),
                             {"name": get_random_string(12), "color": "ff0000",
                              "taxonomy": self._unknown_taxonomy_pk()})
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            self.client.post(reverse("inventory:create_tag"), {"name": get_random_string(12), "color": "ff0000"})
        self.assertIn('Inventory::Action::"createTag" System::"root"', cm.output[0])

    def test_console_update_business_unit_taxonomy_not_logged(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(name=get_random_string(12), meta_business_unit=mbu)
        self._set_policies(self._statement("permit", "createTag"), permissions=(update_tag_action,))
        self.client.force_login(self.user)
        # a taxonomy that the business unit of the tag excludes: not a choice, and not a refusal
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                        {"name": tag.name, "color": "ff0000", "taxonomy": self.taxonomy.pk})
        self.assertIn("taxonomy", response.context["form"].errors)

    def test_console_create_on_root_only(self):
        self._set_policies(self._statement("permit", "createTag", 'resource == System::"root"'))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:create_tag"))
        field = response.context["form"].fields["taxonomy"]
        self.assertEqual(offered(field), [])
        self.assertIsNotNone(field.empty_label)
        name = get_random_string(12)
        response = self.client.post(reverse("inventory:create_tag"), {"name": name, "color": "ff0000"})
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        self.assertIsNone(Tag.objects.get(name=name).taxonomy)

    # console: update

    def test_console_update_keeps_its_taxonomy_without_create_tag(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(permissions=(update_tag_action,))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        field = response.context["form"].fields["taxonomy"]
        self.assertEqual(offered(field), [self.taxonomy])
        self.assertIsNone(field.empty_label)
        new_name = get_random_string(12)
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": new_name, "color": "ff0000", "taxonomy": self.taxonomy.pk})
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        tag.refresh_from_db()
        self.assertEqual(tag.name, new_name)
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": new_name, "color": "ff0000", "taxonomy": self.other_taxonomy.pk})
        self.assertEqual(
            response.context["form"].errors,
            {"taxonomy": ["Select a valid choice. That choice is not one of the available choices."]}
        )
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": new_name, "color": "ff0000"})
        self.assertEqual(response.context["form"].errors, {"taxonomy": ["This field is required."]})

    def test_console_update_no_taxonomy_without_create_tag(self):
        tag = Tag.objects.create(name=get_random_string(12))
        self._set_policies(permissions=(update_tag_action,))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        field = response.context["form"].fields["taxonomy"]
        self.assertEqual(offered(field), [])
        self.assertIsNotNone(field.empty_label)
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": tag.name, "color": "ff0000"})
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)

    def test_console_update_new_taxonomy(self):
        tag = Tag.objects.create(taxonomy=self.taxonomy, name=get_random_string(12))
        self._set_policies(self._statement("permit", "createTag", self._in_taxonomy(self.other_taxonomy)),
                           permissions=(update_tag_action,))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        self.assertEqual(set(offered(response.context["form"].fields["taxonomy"])),
                         {self.taxonomy, self.other_taxonomy})
        response = self.client.post(reverse("inventory:update_tag", args=(tag.pk,)),
                                    {"name": tag.name, "color": "ff0000", "taxonomy": self.other_taxonomy.pk})
        self.assertRedirects(response, reverse("inventory:tags"), fetch_redirect_response=False)
        tag.refresh_from_db()
        self.assertEqual(tag.taxonomy, self.other_taxonomy)

    def test_console_update_business_unit_taxonomies(self):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        mbu_taxonomy = Taxonomy.objects.create(name=get_random_string(12), meta_business_unit=mbu)
        tag = Tag.objects.create(name=get_random_string(12), meta_business_unit=mbu)
        self._set_policies(self._statement("permit", "createTag"), permissions=(update_tag_action,))
        self.client.force_login(self.user)
        response = self.client.get(reverse("inventory:update_tag", args=(tag.pk,)))
        self.assertEqual(offered(response.context["form"].fields["taxonomy"]), [mbu_taxonomy])
