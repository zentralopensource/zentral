from unittest.mock import patch
from django.db import IntegrityError
from django.test import RequestFactory, TestCase
from accounts.models import User
from realms.auth_backends import RealmBackend
from .utils import force_realm, force_realm_user, force_user


class RealmBackendTestCase(TestCase):
    def setUp(self):
        # Every test needs access to the request factory.
        self.factory = RequestFactory()
        self.backend = RealmBackend()
        self.realm = force_realm(enabled_for_login=True)

    def test_no_realm_user(self):
        request = self.factory.get("/")
        self.assertIsNone(self.backend.authenticate(request, None))

    def test_not_for_login_realm_user(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user()
        self.assertFalse(realm_user.realm.enabled_for_login)
        with self.assertRaises(ValueError) as cm:
            self.backend.authenticate(request, realm_user)
        self.assertEqual(cm.exception.args, ("Realm not enabled for login",))

    def test_wrong_realm_user(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        realm_user.email = ""
        with self.assertRaises(ValueError) as cm:
            self.backend.authenticate(request, realm_user)
        self.assertEqual(cm.exception.args, ("Cannot authenticate user with empty email or username",))

    def test_create_user(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        user = self.backend.authenticate(request, realm_user)
        self.assertEqual(user.email, realm_user.email)
        self.assertEqual(user.username, realm_user.username)
        self.assertEqual(user.first_name, realm_user.first_name)
        self.assertEqual(user.last_name, realm_user.last_name)
        self.assertTrue(user.is_remote)

    def test_multiple_users_error(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        force_user(username=realm_user.username)  # username match, not remote
        force_user(email=realm_user.email, remote=True)  # email match, remote
        with self.assertRaises(ValueError) as cm:
            self.backend.authenticate(request, realm_user)
        self.assertEqual(cm.exception.args, (f"Multiple matching users for realm user {realm_user.pk}",))

    def test_update_not_remote_user(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        existing_user = force_user(username=realm_user.username)  # username match, not remote
        self.assertFalse(existing_user.is_remote)
        user = self.backend.authenticate(request, realm_user)
        self.assertEqual(user, existing_user)
        self.assertEqual(user.username, realm_user.username)
        # email not updated
        self.assertEqual(user.email, existing_user.email)
        self.assertNotEqual(user.email, realm_user.email)
        # user is not remote, first and last names not updated
        self.assertEqual(user.first_name, existing_user.first_name)
        self.assertEqual(user.last_name, existing_user.last_name)

    def test_update_remote_user(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        existing_user = force_user(email=realm_user.email, remote=True)  # email match, remote
        self.assertTrue(existing_user.is_remote)
        user = self.backend.authenticate(request, realm_user)
        self.assertEqual(user, existing_user)
        self.assertEqual(user.email, realm_user.email)
        # username not updated
        self.assertEqual(user.username, existing_user.username)
        self.assertNotEqual(user.username, realm_user.username)
        # user is remote, first and last names updated
        self.assertEqual(user.first_name, realm_user.first_name)
        self.assertEqual(user.last_name, realm_user.last_name)

    def test_service_account_no_update(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        existing_sa = force_user(email=realm_user.email, service_account=True)  # email match, service account
        self.assertTrue(existing_sa.is_service_account)
        self.assertIsNone(self.backend.authenticate(request, realm_user))

    def test_inactive_local_user_refused(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        force_user(username=realm_user.username, active=False)
        self.assertIsNone(self.backend.authenticate(request, realm_user))

    def test_inactive_remote_user_refused_not_updated(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        existing_user = force_user(email=realm_user.email, active=False, remote=True)
        self.assertIsNone(self.backend.authenticate(request, realm_user))
        first_name = existing_user.first_name
        existing_user.refresh_from_db()
        self.assertEqual(existing_user.first_name, first_name)
        self.assertNotEqual(existing_user.first_name, realm_user.first_name)

    # a user created between the lookup and the creation

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_remote_user(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        existing_user = force_user(email=realm_user.email, remote=True)
        user = self.backend.authenticate(request, realm_user)
        self.assertEqual(user, existing_user)
        self.assertEqual(user.first_name, realm_user.first_name)

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_inactive_user_refused(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        user = force_user(email=realm_user.email, active=False, remote=True)
        with self.assertLogs("server.accounts.auth_backends", level="WARNING") as cm:
            self.assertIsNone(self.backend.authenticate(request, realm_user))
        self.assertEqual(cm.output, [f"WARNING:server.accounts.auth_backends:Realm user {realm_user.pk} "
                                     f"cannot log in as user {user.pk}"])

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_superuser_refused(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        user = force_user(email=realm_user.email, superuser=True)
        with self.assertLogs("server.accounts.auth_backends", level="WARNING") as cm:
            self.assertIsNone(self.backend.authenticate(request, realm_user))
        self.assertEqual(cm.output, [f"WARNING:server.accounts.auth_backends:Realm user {realm_user.pk} "
                                     f"cannot log in as user {user.pk}"])

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_service_account_refused(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        service_account = force_user(email=realm_user.email, service_account=True)
        with self.assertLogs("server.accounts.auth_backends", level="ERROR") as cm:
            self.assertIsNone(self.backend.authenticate(request, realm_user))
        self.assertEqual(cm.output, [f"ERROR:server.accounts.auth_backends:Realm user {realm_user.pk} "
                                     f"match with service account {service_account.pk}"])

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_multiple_users_error(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        force_user(username=realm_user.username)
        force_user(email=realm_user.email)
        with self.assertRaises(ValueError) as cm:
            self.backend.authenticate(request, realm_user)
        self.assertEqual(cm.exception.args, ("Multiple existing users with same email or username",))

    @patch("realms.models.RealmUser.get_user_for_update")
    def test_concurrent_integrity_error_without_user(self, get_user_for_update):
        get_user_for_update.return_value = None
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        with patch.object(User, "save", side_effect=IntegrityError("yolo")), self.assertRaises(IntegrityError):
            self.backend.authenticate(request, realm_user)

    def test_get_user(self):
        user = force_user()
        self.assertEqual(self.backend.get_user(user.pk), user)

    def test_get_user_unknown(self):
        self.assertIsNone(self.backend.get_user(0))

    def test_get_user_inactive(self):
        user = force_user(active=False)
        self.assertIsNone(self.backend.get_user(user.pk))

    def test_get_user_superuser(self):
        # a realm session ends when its user becomes a superuser
        user = force_user(superuser=True)
        self.assertIsNone(self.backend.get_user(user.pk))

    def test_local_superuser_refused(self):
        request = self.factory.get("/")
        _, realm_user = force_realm_user(realm=self.realm)
        user = force_user(username=realm_user.username, superuser=True)
        with self.assertLogs("server.accounts.auth_backends", level="WARNING") as cm:
            self.assertIsNone(self.backend.authenticate(request, realm_user))
        self.assertEqual(cm.output, [f"WARNING:server.accounts.auth_backends:Realm user {realm_user.pk} "
                                     f"cannot log in as user {user.pk}"])

    def test_get_user_service_account(self):
        user = force_user(service_account=True)
        self.assertIsNone(self.backend.get_user(user.pk))
