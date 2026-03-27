from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from .utils import force_store


class StoreViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "stores"

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_one_not_provisioned_store(self):
        store = force_store()
        self.login("stores.view_store")
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/index.html")
        self.assertContains(response, "Store (1)")
        self.assertContains(response, store.name)
        self.assertContains(response, '<span class="store-backend">HTTP</span>')

    def test_index_one_provisioned_store(self):
        store = force_store(provisioned=True)
        self.login("stores.view_store")
        response = self.client.get(reverse("stores:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/index.html")
        self.assertContains(response, "Store (1)")
        self.assertContains(response, store.name)
        self.assertNotContains(response, '<span class="store-backend">HTTP</span>')

    # store

    def test_store_redirect(self):
        store = force_store()
        self.login_redirect("store", store.pk)

    def test_store_permission_denied(self):
        store = force_store()
        self.login()
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_store_not_provisioned(self):
        store = force_store()
        self.login("stores.view_store")
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/store_detail.html")
        self.assertContains(response, store.name)
        self.assertContains(response, '<span class="store-backend">HTTP</span>')
        self.assertContains(response, "endpoint_url")

    def test_store_provisioned(self):
        store = force_store(provisioned=True)
        self.login("stores.view_store")
        response = self.client.get(reverse("stores:store", args=(store.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "stores/store_detail.html")
        self.assertContains(response, store.name)
        self.assertNotContains(response, '<span class="store-backend">HTTP</span>')
        self.assertNotContains(response, "endpoint_url")
