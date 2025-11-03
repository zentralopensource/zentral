from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import APIToken, User


class UsersModelsTestCase(TestCase):

    def test_api_token_serialize_for_event_keys_only(self):
        # Given
        username = get_random_string(19)
        email = "{}@zentral.io".format(get_random_string(12))

        token, _ = APIToken.objects.update_or_create_for_user(
            User.objects.create_user(username, email))

        # When
        actual = token.serialize_for_event(keys_only=True)

        # Then
        self.assertEqual(actual, {
            "pk": token.pk,
            "username": username,
            "email": email
        })
