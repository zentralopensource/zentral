from functools import reduce
import operator
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from accounts.models import User
from .utils import force_store


class StoreViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

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

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("stores:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_one_not_provisioned_store(self):
        store = force_store()
        self._login("stores.view_store")
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/index.html")
        self.assertContains(response, "Store (1)")
        self.assertContains(response, store.name)
        self.assertContains(response, '<span class="store-backend">HTTP</span>')

    def test_index_one_provisioned_store(self):
        store = force_store(provisioned=True)
        self._login("stores.view_store")
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/index.html")
        self.assertContains(response, "Store (1)")
        self.assertContains(response, store.name)
        self.assertNotContains(response, '<span class="store-backend">HTTP</span>')

    # store

    def test_store_redirect(self):
        store = force_store()
        self._login_redirect(reverse("stores:store", args=(store.pk,)))

    def test_store_permission_denied(self):
        store = force_store()
        self._login()
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_store_not_provisioned(self):
        store = force_store()
        self._login("stores.view_store")
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/store_detail.html")
        self.assertContains(response, store.name)
        self.assertContains(response, '<span class="store-backend">HTTP</span>')
        self.assertContains(response, "endpoint_url")

    def test_store_provisioned(self):
        store = force_store(provisioned=True)
        self._login("stores.view_store")
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/store_detail.html")
        self.assertContains(response, store.name)
        self.assertNotContains(response, '<span class="store-backend">HTTP</span>')
        self.assertNotContains(response, "endpoint_url")
