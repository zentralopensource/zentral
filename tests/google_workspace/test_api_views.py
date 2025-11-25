from functools import reduce
import operator
from django.test import TestCase, override_settings
from django.urls import reverse
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.utils.crypto import get_random_string
from accounts.models import User, APIToken
from zentral.contrib.google_workspace.models import Connection


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class ApiViewsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        # user
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.service_account.groups.set([cls.group])
        cls.user.groups.set([cls.group])

        _, cls.api_key = APIToken.objects.update_or_create_for_user(cls.service_account)

    # utils
    def set_permissions(self, *permissions):
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

    def login(self, *permissions):
        self.set_permissions(*permissions)
        self.client.force_login(self.user)

    def login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _make_query(self, verb, url, data=None, include_token=True):
        kwargs = {}
        if data is not None:
            kwargs["content_type"] = "application/json"
            kwargs["data"] = data
        if include_token:
            kwargs["HTTP_AUTHORIZATION"] = f"Token {self.api_key}"
        return getattr(self.client, verb)(url, **kwargs)

    def post(self, url, include_token=True):
        return self._make_query("post", url, include_token=include_token)

    def _given_connection(self, user_info=f"""{{
                            "refresh_token": "{get_random_string(12)}",
                            "client_id": "{get_random_string(12)}",
                            "client_secret": "{get_random_string(12)}"
                        }}"""):
        name = get_random_string(12)
        client_config = """{"web":{}}"""
        connection = Connection.objects.create(name=name)
        connection.set_client_config(client_config)
        if user_info:
            connection.set_user_info(user_info)
        connection.save()

        return connection

    # SyncTagsView

    def test_group_tag_mappings_task_unauthorized(self):
        connection = self._given_connection()
        response = self.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)),
                             include_token=False)
        self.assertEqual(response.status_code, 401)

    def test_group_tag_mappings_task_devices_permission_denied(self):
        connection = self._given_connection()
        response = self.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_group_tag_mappings_task(self):
        connection = self._given_connection()
        self.set_permissions("google_workspace.view_connection")
        response = self.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])

    def test_user_group_tag_mappings_task_unauthorized(self):
        connection = self._given_connection()
        response = self.client.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 401)

    def test_user_group_tag_mappings_task_permission_denied(self):
        connection = self._given_connection()
        self.login()
        response = self.client.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_user_group_tag_mappings_task_devices(self):
        connection = self._given_connection()
        self.login("google_workspace.view_connection")
        response = self.client.post(reverse("google_workspace_api:sync_tags", args=(connection.pk,)))
        self.assertEqual(response.status_code, 201)
        self.assertEqual(sorted(response.json().keys()), ['task_id', 'task_result_url'])