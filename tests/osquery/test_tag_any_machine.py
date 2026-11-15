
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import APIToken, User
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.request_case import RequestCase
from tests.zentral_test_utils.tag_any_machine_case import TagAnyMachineAPISaveCase, TagAnyMachineFormSaveCase
from zentral.contrib.osquery.models import Query


# The tag of a query: the machines get it when a result comes in.


class QueryTagCase:
    tam_permissions = ("osquery.add_query", "osquery.change_query")
    tam_many = False
    tam_error_path = ("tag",)
    tam_field_name = "tag"

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

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "osquery"

    def _get_api_key(self):
        return self.api_key

    def tam_force_object(self, tags):
        return Query.objects.create(name=get_random_string(12), sql="select 1 from users;",
                                    tag=tags[0] if tags else None)

    def tam_saved_tags(self, response=None, obj=None):
        query = Query.objects.get(pk=obj.pk) if obj else Query.objects.get(name=self.name)
        return {query.tag} if query.tag else set()


class QueryAPITestCase(QueryTagCase, TagAnyMachineAPISaveCase, TestCase, LoginCase, RequestCase):
    def payload(self, name, tags, omit_tags=False):
        payload = {"name": name, "sql": "select 2 from users;"}
        if not omit_tags:
            payload["tag"] = tags[0].pk if tags else None
        return payload

    def tam_create(self, tags):
        self.name = get_random_string(12)
        return self.post(reverse("osquery_api:queries"), self.payload(self.name, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        return self.put(reverse("osquery_api:query", args=(obj.pk,)), self.payload(obj.name, tags, omit_tags))


class QueryFormTestCase(QueryTagCase, TagAnyMachineFormSaveCase, TestCase, LoginCase):
    def data(self, name, tags):
        data = {"name": name, "sql": "select 2 from users;"}
        if tags:
            data["tag"] = tags[0].pk
        return data

    def tam_create(self, tags):
        self.client.force_login(self.user)
        self.name = get_random_string(12)
        return self.client.post(reverse("osquery:create_query"), self.data(self.name, tags))

    def tam_update(self, obj, tags, omit_tags=False):
        self.client.force_login(self.user)
        return self.client.post(reverse("osquery:update_query", args=(obj.pk,)), self.data(obj.name, tags))

    def tam_get_update_form(self, obj):
        self.client.force_login(self.user)
        return self.client.get(reverse("osquery:update_query", args=(obj.pk,)))
