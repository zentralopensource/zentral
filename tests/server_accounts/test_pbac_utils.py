from cedarpy import format_policies
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.cedar import policies_cache
from pbac.engine import engine
from pbac.entities import Principal, Request
from pbac.utils import check_request


class CheckRequestTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(
            get_random_string(12),
            f"{get_random_string(12)}@zentral.com",
            is_superuser=False,
        )
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        Policy.objects.create(
            name="Tests",
            source=format_policies(
                f'permit (principal in Role::"{cls.group.pk}", '
                f'action == Accounts::Action::"viewUser", resource);'
            ),
        )

    def setUp(self):
        policies_cache.clear()
        self.request = RequestFactory().get("/")

    def _pbac_request(self, perm):
        return Request(
            Principal.from_user(self.user),
            engine.legacy_perm_actions[perm],
            engine.system_any_resource,
        )

    def test_check_request_permitted(self):
        pbac_request = self._pbac_request("accounts.view_user")
        with self.assertNoLogs("zentral.pbac.utils"):
            check_request(self.request, pbac_request)
        self.assertTrue(pbac_request.is_authorized)

    def test_check_request_refused(self):
        pbac_request = self._pbac_request("accounts.delete_user")
        with self.assertLogs("zentral.pbac.utils", level="ERROR") as cm, self.assertRaises(PermissionDenied):
            check_request(self.request, pbac_request)
        self.assertFalse(pbac_request.is_authorized)
        self.assertEqual(len(cm.records), 1)
        self.assertEqual(cm.records[0].getMessage(), f"Permission denied {pbac_request!r}")
        self.assertIs(cm.records[0].request, self.request)
