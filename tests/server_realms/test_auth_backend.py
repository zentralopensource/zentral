from django.test import RequestFactory, TestCase
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
