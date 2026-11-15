from django.contrib.auth.models import Group
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string
from rest_framework.request import Request as DRFRequest

from accounts.models import Policy, User
from pbac.engine import engine
from zentral.core.stores.api_views import StoreDetail
from zentral.core.stores.pbac import ViewStoreSecretsRequest, view_store_secrets_action
from zentral.core.stores.serializers import StoreSerializer
from .utils import force_store


class StoresPBACTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    def _force_store(self):
        return force_store(backend_kwargs={"endpoint_url": "https://www.example.com",
                                           "username": "yolo",
                                           "password": "fomo"}).instance

    def test_view_store_secrets_action_groups(self):
        self.assertEqual(
            sorted(str(p) for p in view_store_secrets_action.parents),
            ['Action::"GlobalAdminActions"', 'Stores::Action::"AdminActions"'],
        )

    def test_view_store_secrets_request(self):
        store = self._force_store()
        request = ViewStoreSecretsRequest(self.user, store)
        self.assertEqual(str(request.action), 'Stores::Action::"viewStoreSecrets"')
        self.assertEqual(request.resource.full_type, "Stores::Store")
        self.assertEqual(request.resource.id, str(store.pk))
        self.assertEqual(request.resource.parents, [])
        self.assertEqual(request.context, {})

    def test_view_store_secrets_admin_actions(self):
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal in Role::"{self.group.pk}", action in Action::"GlobalAdminActions", resource);'
        )
        request = ViewStoreSecretsRequest(self.user, self._force_store())
        engine.authorize_request(request)
        self.assertTrue(request.is_authorized)

    def test_view_store_secrets_viewer_and_user_actions(self):
        Policy.objects.create(
            name=get_random_string(12),
            source=(f'permit (principal in Role::"{self.group.pk}",'
                    ' action in [Action::"GlobalViewerActions", Action::"GlobalUserActions"], resource);')
        )
        request = ViewStoreSecretsRequest(self.user, self._force_store())
        engine.authorize_request(request)
        self.assertFalse(request.is_authorized)

    def test_serializer_without_decision_hashes_the_secrets(self):
        store = self._force_store()
        data = StoreSerializer(store).data
        self.assertNotIn("password", data["http_kwargs"])
        self.assertEqual(data["http_kwargs"]["password_hash"],
                         "48ffcddb8b19a5f98d4b1b8c08b4024b12b6f24affeb50b1265aed528a2dd671")

    def test_api_view_read_serializer_without_object(self):
        drf_request = DRFRequest(RequestFactory().get("/"))
        drf_request.user = self.user
        view = StoreDetail(request=drf_request, format_kwarg=None, kwargs={})
        serializer = view.get_serializer()
        self.assertEqual(serializer.context["pks_with_secrets"], set())
