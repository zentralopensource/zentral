from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User
from datetime import timedelta, date


class UsersModelsTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        # Given
        cls.username = get_random_string(19)
        cls.email = "{}@zentral.io".format(get_random_string(12))
        cls.user = User.objects.create_user(cls.username, cls.email)

    def test_user_serialize_for_event_keys_only(self):
        # When
        actual = self.user.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": self.user.pk,
            "username": self.username,
            "email": self.email
        })

    def test_api_token_serialize_for_event(self):
        token, _ = APIToken.objects.create_for_user(self.user, name='MyTestToken')

        # When
        actual = token.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": token.pk,
            "name": 'MyTestToken'
        })

        # When
        actual = token.serialize_for_event(keys_only=False)

        # Then
        self.assertEqual(actual, {
            "pk": token.pk,
            "name": 'MyTestToken',
            "user": self.user.serialize_for_event(),
            "expiry": token.expiry,
            "created_at": token.created_at,
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
