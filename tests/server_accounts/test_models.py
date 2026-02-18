from datetime import timedelta
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import OIDCAPITokenIssuer, User


class OIDCAPITokenIssuerIssuerTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.service_account = User.objects.create(
            username=get_random_string(12),
            email="{}@zentral.io".format(get_random_string(12)),
            is_service_account=True
        )

    def _create_token_issuer(
            self,
            issuer_uri: str):
        return OIDCAPITokenIssuer.objects.create(
            user=self.service_account,
            name=get_random_string(12),
            description="",
            issuer_uri=issuer_uri,
            audience=f"aud-{get_random_string(10)}",
            cel_condition="",
            max_duration=timedelta(seconds=60),
        )

    def test_validator_accepts_https_url(self):
        self._create_token_issuer("https://issuer.zentral.com").full_clean()

    def test_validator_rejects_http_url(self):
        with self.assertRaises(ValidationError) as ctx:
            self._create_token_issuer("http://issuer.zentral.com").full_clean()
        self.assertIn("https://", str(ctx.exception).lower())

    def test_validator_rejects_invalid_url(self):
        with self.assertRaises(ValidationError):
            self._create_token_issuer("not a url").full_clean()

    def test_validator_rejects_missing_scheme(self):
        with self.assertRaises(ValidationError):
            self._create_token_issuer("issuer.zentral.com").full_clean()
