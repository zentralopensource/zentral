from datetime import date, timedelta
from importlib import import_module

from accounts.models import APIToken, OIDCAPITokenIssuer, User
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string

from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from zentral.utils.time import naive_utcnow


class UsersModelsTestCase(TestCase, SerializeForEventAssertions):

    def test_api_token_serialize_for_event_is_json_native(self):
        token, _ = APIToken.objects.create_for_user(
            self.user, expiry=naive_utcnow() + timedelta(days=1), name=get_random_string(12))
        self.assert_serialize_for_event_is_json_native(token)

    @classmethod
    def setUpTestData(cls):
        # Given
        cls.username = get_random_string(19)
        cls.email = "{}@zentral.io".format(get_random_string(12))
        cls.user = User.objects.create_user(cls.username, cls.email)
        cls.service_account = User.objects.create_user(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        cls.oidc_api_token_issuer = OIDCAPITokenIssuer.objects.create(
            user=cls.service_account,
            name=get_random_string(12),
            issuer_uri="https://issuer.zentral.com",
            audience=f"aud-{get_random_string(10)}",
        )

    # user

    def test_user_serialize_for_event_keys_only(self):
        # When
        actual = self.user.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": self.user.pk,
            "username": self.username,
            "email": self.email
        })

    # API token

    def test_api_token_serialize_for_event(self):
        token, _ = APIToken.objects.create_for_user(self.user, name='MyTestToken')

        # When
        actual = token.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": str(token.pk),
            "name": 'MyTestToken'
        })

        # When
        actual = token.serialize_for_event(keys_only=False)

        # Then
        self.assertEqual(actual, {
            "pk": str(token.pk),
            "name": 'MyTestToken',
            "user": self.user.serialize_for_event(),
            "expiry": token.expiry,
            "created_at": token.created_at.isoformat(),
            "hashed_key": token.hashed_key
        })

    def test_api_token_expiry(self):

        expiry_date = date.today() + timedelta(days=1)
        token, _ = APIToken.objects.create_for_user(self.user,
                                                    name='MyActiveTestToken',
                                                    expiry=expiry_date)
        self.assertEqual(token.is_active(), True)

        expired_date = date.today() - timedelta(days=1)
        token, _ = APIToken.objects.create_for_user(self.user,
                                                    name='MyExpiredTestToken',
                                                    expiry=expired_date)
        self.assertEqual(token.is_expired(), True)

    # OIDC API token issuer

    def test_oidc_api_token_issuer_serialize_for_event_keys_only(self):
        self.assertEqual(
            self.oidc_api_token_issuer.serialize_for_event(keys_only=True),
            {"pk": str(self.oidc_api_token_issuer.pk),
             "name": self.oidc_api_token_issuer.name}
        )

    # superusers

    def test_remote_user_is_not_a_superuser(self):
        user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                        is_remote=True, is_superuser=True)
        user.refresh_from_db()
        self.assertFalse(user.is_superuser)
        user.is_superuser = True
        user.save()
        user.refresh_from_db()
        self.assertFalse(user.is_superuser)

    def test_service_account_is_not_a_superuser(self):
        self.service_account.is_superuser = True
        self.service_account.save()
        self.service_account.refresh_from_db()
        self.assertFalse(self.service_account.is_superuser)

    def test_migration_removes_the_superuser_flag_of_the_remote_users(self):
        local_superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                                   is_superuser=True)
        remote_user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                               is_remote=True)
        # a remote superuser of before the upgrade, that User.save cannot write anymore
        User.objects.filter(pk=remote_user.pk).update(is_superuser=True)
        migration = import_module("accounts.migrations.0025_remote_users_are_not_superusers")
        migration.remove_the_superuser_flag_of_the_remote_users(apps, None)
        remote_user.refresh_from_db()
        self.assertFalse(remote_user.is_superuser)
        local_superuser.refresh_from_db()
        self.assertTrue(local_superuser.is_superuser)

    def test_create_api_token_for_superuser_refused(self):
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                             is_superuser=True)
        with self.assertRaises(ValueError) as cm:
            APIToken.objects.create_for_user(superuser)
        self.assertEqual(cm.exception.args, ("A superuser has no API token",))
        self.assertFalse(APIToken.objects.filter(user=superuser).exists())

    def test_migration_deletes_the_api_tokens_of_the_superusers(self):
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io")
        APIToken.objects.create_for_user(superuser)
        # a token of before the upgrade, that create_for_user cannot write anymore
        User.objects.filter(pk=superuser.pk).update(is_superuser=True)
        user_token, _ = APIToken.objects.create_for_user(self.user)
        service_account_token, _ = APIToken.objects.create_for_user(self.service_account)
        migration = import_module("accounts.migrations.0026_superusers_have_no_api_token")
        migration.delete_the_api_tokens_of_the_superusers(apps, None)
        self.assertFalse(APIToken.objects.filter(user=superuser).exists())
        self.assertEqual(
            set(APIToken.objects.filter(user__in=(self.user, self.service_account))),
            {user_token, service_account_token},
        )
