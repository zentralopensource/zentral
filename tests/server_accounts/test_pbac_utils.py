from cedarpy import format_policies
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory, TestCase
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from pbac.engine import engine
from pbac.entities import Principal, Request
from pbac.utils import check_request, could_be_permitted, refused_requests


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
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm, self.assertRaises(PermissionDenied):
            check_request(self.request, pbac_request)
        self.assertFalse(pbac_request.is_authorized)
        self.assertEqual(len(cm.records), 1)
        self.assertEqual(cm.records[0].levelname, "WARNING")
        self.assertEqual(cm.records[0].getMessage(), f"Permission denied {pbac_request!r}")
        self.assertIs(cm.records[0].request, self.request)

    def test_check_request_inactive_user_refused(self):
        self.user.is_active = False
        pbac_request = self._pbac_request("accounts.view_user")
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm, self.assertRaises(PermissionDenied):
            check_request(self.request, pbac_request)
        self.assertFalse(pbac_request.is_authorized)
        self.assertEqual(len(cm.records), 1)

    def test_refused_requests(self):
        permitted = self._pbac_request("accounts.view_user")
        refused = self._pbac_request("accounts.delete_user")
        other_refused = self._pbac_request("accounts.add_user")
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            result = refused_requests(self.request, (r for r in (permitted, refused, other_refused)))
        self.assertEqual(result, [refused, other_refused])
        self.assertTrue(permitted.is_authorized)
        self.assertEqual([record.getMessage() for record in cm.records],
                         [f"Permission denied {refused!r}", f"Permission denied {other_refused!r}"])
        self.assertTrue(all(record.request is self.request for record in cm.records))

    def test_refused_requests_all_permitted(self):
        with self.assertNoLogs("zentral.pbac.utils"):
            self.assertEqual(refused_requests(self.request, [self._pbac_request("accounts.view_user")]), [])

    def test_refused_requests_empty(self):
        with self.assertNoLogs("zentral.pbac.utils"):
            self.assertEqual(refused_requests(self.request, []), [])

    def test_could_be_permitted(self):
        self.request.user = self.user
        with self.assertNoLogs("zentral.pbac.utils"):
            self.assertTrue(could_be_permitted(self.request, engine.legacy_perm_actions["accounts.view_user"]))

    def test_could_be_permitted_refused(self):
        self.request.user = self.user
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            self.assertFalse(could_be_permitted(self.request, engine.legacy_perm_actions["accounts.delete_user"]))
        self.assertEqual(
            cm.records[0].getMessage(),
            f'Permission denied Request <User::"{self.user.pk}" Accounts::Action::"deleteUser" ?> Denied'
        )
        self.assertIs(cm.records[0].request, self.request)


class RequestReprTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.com")

    def test_decision(self):
        pbac_request = Request(Principal.from_user(self.user), engine.legacy_perm_actions["accounts.view_user"],
                               engine.system_any_resource)
        self.assertEqual(
            repr(pbac_request),
            f'Request <User::"{self.user.pk}" Accounts::Action::"viewUser" System::"any"> Pending'
        )

    def test_unknown_resource(self):
        # a list or a preview on any resource: the request cannot tell them apart
        pbac_request = Request(Principal.from_user(self.user), engine.legacy_perm_actions["accounts.view_user"], None)
        self.assertEqual(repr(pbac_request),
                         f'Request <User::"{self.user.pk}" Accounts::Action::"viewUser" ?> Pending')

    def test_unknown_context(self):
        pbac_request = Request(Principal.from_user(self.user), engine.legacy_perm_actions["accounts.view_user"],
                               engine.system_any_resource, unknown_context=True)
        self.assertTrue(repr(pbac_request).endswith("> Pending (preview)"))
