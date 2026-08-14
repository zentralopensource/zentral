from datetime import date, timedelta

from accounts.models import APIToken, OIDCAPITokenIssuer, Policy, User
from django.contrib.auth.models import Group
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

    # can_issue_credentials_for

    def test_can_issue_credentials_for_no_roles(self):
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))

    def test_can_issue_credentials_for_shared_role(self):
        group = Group.objects.create(name=get_random_string(12))
        self.user.groups.set([group])
        self.service_account.groups.set([group])
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))

    def test_can_issue_credentials_for_subset_of_roles(self):
        # the requester may hold more roles than the target
        group = Group.objects.create(name=get_random_string(12))
        self.user.groups.set([group, Group.objects.create(name=get_random_string(12))])
        self.service_account.groups.set([group])
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))

    def test_cannot_issue_credentials_for_ungrantable_role(self):
        self.service_account.groups.set([Group.objects.create(name=get_random_string(12))])
        self.assertFalse(self.user.can_issue_credentials_for(self.service_account))

    def test_superuser_can_issue_credentials_for_ungrantable_role(self):
        self.service_account.groups.set([Group.objects.create(name=get_random_string(12))])
        self.user.is_superuser = True
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))

    def test_service_account_requester_gets_no_superuser_bypass(self):
        # save() forces it False on a service account, and the auth backend ignores it too
        requester = User.objects.create_user(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True,
        )
        requester.is_superuser = True
        self.service_account.groups.set([Group.objects.create(name=get_random_string(12))])
        self.assertFalse(requester.can_issue_credentials_for(self.service_account))

    def test_cannot_issue_credentials_for_service_account_named_by_policy(self):
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == ServiceAccount::"{self.service_account.pk}", action, resource);',
        )
        self.assertFalse(self.user.can_issue_credentials_for(self.service_account))

    def test_cannot_issue_credentials_for_service_account_named_by_inactive_policy(self):
        Policy.objects.create(
            name=get_random_string(12),
            is_active=False,
            source=f'permit (principal == ServiceAccount::"{self.service_account.pk}", action, resource);',
        )
        self.assertFalse(self.user.can_issue_credentials_for(self.service_account))

    def test_can_issue_credentials_for_service_account_named_by_policy_as_superuser(self):
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == ServiceAccount::"{self.service_account.pk}", action, resource);',
        )
        self.user.is_superuser = True
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))

    def test_can_issue_credentials_for_service_account_named_as_user_by_policy(self):
        # a User:: reference cannot match a service account principal
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == User::"{self.service_account.pk}", action, resource);',
        )
        self.assertTrue(self.user.can_issue_credentials_for(self.service_account))
