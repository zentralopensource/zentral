from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.wsone.models import Instance


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class WSOneSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string())
        cls.group = Group.objects.create(name=get_random_string())
        cls.user.groups.set([cls.group])
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.bu = cls.mbu.create_enrollment_business_unit()

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
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
        self.client.force_login(self.user)

    def _force_instance(self):
        instance = Instance.objects.create(
            business_unit=self.bu,
            server_url="https://{}.example.com".format(get_random_string(8)),
            client_id=get_random_string(),
            token_url="https://{}.example.com".format(get_random_string(8)),
            username=get_random_string()
        )
        instance.set_api_key(get_random_string())
        instance.set_client_secret(get_random_string())
        instance.set_password(get_random_string())
        instance.save()
        return instance

    # instances

    def test_instances_redirect(self):
        self._login_redirect(reverse("wsone:instances"))

    def test_instances_permission_denied(self):
        self._login()
        response = self.client.get(reverse("wsone:instances"))
        self.assertEqual(response.status_code, 403)

    def test_instances(self):
        instance = self._force_instance()
        self._login("wsone.view_instance")
        response = self.client.get(reverse("wsone:instances"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, instance.hostname)
        self.assertNotContains(response, reverse("wsone:instance_events",
                                                 args=(instance.pk,)))
        self.assertNotContains(response, reverse("wsone:instance_events_store_redirect",
                                                 args=(instance.pk,)))

    # instance events

    def test_instance_events_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("wsone:instance_events", args=(instance.pk,)))

    def test_instance_events_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("wsone:instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_instance_events_ok(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        instance = self._force_instance()
        self._login("wsone.view_instance")
        response = self.client.get(reverse("wsone:instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_events.html")

    def test_fetch_instance_events_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("wsone:fetch_instance_events", args=(instance.pk,)))

    def test_fetch_instance_events_permission_denied(self):
        instance = self._force_instance()
        self._login("wsone.change_instance")
        response = self.client.get(reverse("wsone:fetch_instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_instance_events_ok(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        instance = self._force_instance()
        self._login("wsone.view_instance")
        response = self.client.get(reverse("wsone:fetch_instance_events", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # create instance

    def test_create_instance_redirect(self):
        self._login_redirect(reverse("wsone:create_instance"))

    def test_create_instance_permission_denied(self):
        self._login()
        response = self.client.get(reverse("wsone:create_instance"))
        self.assertEqual(response.status_code, 403)

    def test_create_instance_get(self):
        self._login("wsone.add_instance")
        response = self.client.get(reverse("wsone:create_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_form.html")

    def test_create_instance_post(self):
        self._login("wsone.add_instance", "wsone.view_instance")
        server_url = "https://{}.example.com".format(get_random_string(8))
        api_key = get_random_string()
        client_secret = get_random_string()
        password = get_random_string()
        response = self.client.post(reverse("wsone:create_instance"),
                                    {"business_unit": self.bu.pk,
                                     "server_url": server_url,
                                     "excluded_groups": "un,  deux ",
                                     "api_key": api_key,
                                     "client_id": get_random_string(),
                                     "client_secret": client_secret,
                                     "token_url": "https://{}.example.com".format(get_random_string(8)),
                                     "username": get_random_string(),
                                     "password": password},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_detail.html")
        self.assertContains(response, server_url)
        instance = response.context["object"]
        self.assertEqual(instance.server_url, server_url)
        self.assertEqual(instance.excluded_groups, ["un", "deux"])
        self.assertEqual(instance.get_api_key(), api_key)
        self.assertEqual(instance.get_client_secret(), client_secret)
        self.assertEqual(instance.get_password(), password)

    # update instance

    def test_update_instance_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("wsone:update_instance", args=(instance.pk,)))

    def test_update_instance_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("wsone:update_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_instance_get(self):
        instance = self._force_instance()
        self._login("wsone.change_instance")
        response = self.client.get(reverse("wsone:update_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_form.html")

    def test_update_instance_post(self):
        instance = self._force_instance()
        self._login("wsone.change_instance", "wsone.view_instance")
        api_key = get_random_string()
        client_secret = get_random_string()
        password = get_random_string()
        response = self.client.post(reverse("wsone:update_instance", args=(instance.pk,)),
                                    {"business_unit": instance.business_unit.pk,
                                     "server_url": instance.server_url,
                                     "excluded_groups": "un,  deux ",
                                     "api_key": api_key,
                                     "client_id": instance.client_id,
                                     "client_secret": client_secret,
                                     "token_url": "https://{}.example.com".format(get_random_string(8)),
                                     "username": instance.username,
                                     "password": password},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_detail.html")
        instance2 = response.context["object"]
        self.assertEqual(instance2, instance)
        self.assertEqual(instance2.server_url, instance.server_url)
        self.assertEqual(instance2.excluded_groups, ["un", "deux"])
        self.assertEqual(instance2.get_api_key(), api_key)
        self.assertEqual(instance2.get_client_secret(), client_secret)
        self.assertEqual(instance2.get_password(), password)

    # delete instance

    def test_delete_instance_redirect(self):
        instance = self._force_instance()
        self._login_redirect(reverse("wsone:delete_instance", args=(instance.pk,)))

    def test_delete_instance_permission_denied(self):
        instance = self._force_instance()
        self._login()
        response = self.client.get(reverse("wsone:delete_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_instance_get(self):
        instance = self._force_instance()
        self._login("wsone.delete_instance")
        response = self.client.get(reverse("wsone:delete_instance", args=(instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_confirm_delete.html")

    def test_delete_instance_post(self):
        instance = self._force_instance()
        self._login("wsone.delete_instance", "wsone.view_instance")
        response = self.client.post(reverse("wsone:delete_instance", args=(instance.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "wsone/instance_list.html")
        self.assertNotContains(response, instance.hostname)
