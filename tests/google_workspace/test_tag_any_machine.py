import json
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from tests.zentral_test_utils.tag_any_machine_case import TagAnyMachineAPISaveCase, TagAnyMachineFormSaveCase
from zentral.contrib.google_workspace.models import Connection, GroupTagMapping


# The tags of a group tag mapping: the tag sync gives them to machines.


class GroupTagMappingCase:
    tam_permissions = ("google_workspace.add_grouptagmapping", "google_workspace.change_grouptagmapping")

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

    def setUp(self):
        super().setUp()
        build = self.enterContext(patch("zentral.contrib.google_workspace.api_client.build"))
        # each group is in the connection
        build.return_value.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"email": "group@zentral.com"}]
        }

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "google_workspace"

    def _get_api_key(self):
        return self.api_key

    def force_connection(self):
        connection = Connection.objects.create(name=get_random_string(12))
        connection.set_client_config(json.dumps({"web": {}}))
        connection.set_user_info(json.dumps({"refresh_token": get_random_string(12),
                                             "client_id": get_random_string(12),
                                             "client_secret": get_random_string(12)}))
        connection.save()
        return connection

    def tam_force_object(self, tags):
        mapping = GroupTagMapping.objects.create(group_email="group@zentral.com", connection=self.force_connection())
        mapping.tags.set(tags)
        return mapping

    def tam_saved_tags(self, response=None, obj=None):
        if obj is None:
            obj = GroupTagMapping.objects.get(connection=self.connection)
        return set(GroupTagMapping.objects.get(pk=obj.pk).tags.all())

    # a mapping always has tags

    def test_tam_create_without_tag_without_the_action(self):
        self.tam_set_policies(tag_action=False)
        self.tam_assert_no_tag(self.tam_create([]))

    def test_tam_update_remove_the_tags_without_the_action(self):
        tag = self.tam_force_tag()
        obj = self.tam_force_object([tag])
        self.tam_set_policies(tag_action=False)
        self.tam_assert_no_tag(self.tam_update(obj, []))
        self.assertEqual(self.tam_saved_tags(obj=obj), {tag})


class GroupTagMappingAPITestCase(GroupTagMappingCase, TagAnyMachineAPISaveCase, TestCase, LoginCase, RequestCase):
    def payload(self, connection, tags, omit_tags=False):
        payload = {"connection": str(connection.pk), "group_email": "group@zentral.com"}
        if not omit_tags:
            payload["tags"] = [tag.pk for tag in tags]
        return payload

    def tam_create(self, tags):
        self.connection = self.force_connection()
        return self.post(reverse("google_workspace_api:group_tag_mappings"), self.payload(self.connection, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse("google_workspace_api:group_tag_mapping", args=(obj.pk,)),
                        self.payload(obj.connection, tags, omit_tags))

    def tam_assert_no_tag(self, response):
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {"tags": ["This list may not be empty."]})


class GroupTagMappingFormTestCase(GroupTagMappingCase, TagAnyMachineFormSaveCase, TestCase, LoginCase):
    def data(self, tags):
        return {"group_email": "group@zentral.com", "tags": [tag.pk for tag in tags]}

    def tam_create(self, tags):
        self.client.force_login(self.user)
        self.connection = self.force_connection()
        return self.client.post(reverse("google_workspace:create_group_tag_mapping", args=(self.connection.pk,)),
                                self.data(tags))

    def tam_update(self, obj, tags, omit_tags=False):
        self.client.force_login(self.user)
        return self.client.post(
            reverse("google_workspace:update_group_tag_mapping", args=(obj.connection.pk, obj.pk)),
            self.data(tags)
        )

    def tam_get_update_form(self, obj):
        self.client.force_login(self.user)
        return self.client.get(
            reverse("google_workspace:update_group_tag_mapping", args=(obj.connection.pk, obj.pk))
        )

    def tam_assert_no_tag(self, response):
        self.assertEqual(response.context["form"].errors, {"tags": ["This field is required."]})
