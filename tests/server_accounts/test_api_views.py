from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from zentral.core.events.base import AuditEvent

from accounts.models import APIToken, OIDCAPITokenIssuer, User
from accounts import api_views as token_issuers_module
from accounts.api_views import OIDCAPITokenExchangeView

from tests.zentral_test_utils.zentral_api_test_case import ZentralAPITestCase


class OIDCAPITokenExchangeViewTestCase(ZentralAPITestCase):

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        # issuer
        cls.issuer = cls._create_token_issuer(user=cls.service_account)

    @staticmethod
    def _create_token_issuer(
            user: User,
            cel_condition: str = ""):
        return OIDCAPITokenIssuer.objects.create(
            user=user,
            name=get_random_string(12),
            description="",
            issuer_uri=f"https://issuer_{get_random_string(5)}.zentral.com",
            audience=f"aud-{get_random_string(10)}",
            cel_condition=cel_condition,
            max_duration=timedelta(seconds=60),
        )

    def post(self, url, data=None):
        return super().post(url=url, data=data, include_token=False)

    # OIDCAPITokenExchangeView

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_exchange_success_default_name_and_capped_duration(self, post_event):
        now = datetime(2026, 2, 17, 12, 0, 0)

        verify_jws_mock = Mock(return_value={
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        })

        with patch.object(token_issuers_module, "verify_jws_with_discovery", verify_jws_mock), \
             patch.object(timezone, "now", return_value=now), \
             self.captureOnCommitCallbacks(execute=True) as callbacks:

            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
                data={
                    "jwt": "header.payload.sig",
                    "duration": self.issuer.max_duration.seconds * 2
                })

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["user"]["username"], self.service_account.username)
        self.assertEqual(response.data["user"]["email"], self.service_account.email)

        self.assertEqual(response.data["token"]["name"], self.issuer.name)

        self.assertIn("secret", response.data["token"])
        self.assertTrue(response.data["token"]["pk"])

        api_token = APIToken.objects.get(pk=response.data["token"]["pk"])
        self.assertEqual(api_token.user_id, self.service_account.id)
        self.assertEqual(api_token.name, self.issuer.name)
        self.assertEqual(api_token.expiry, now + self.issuer.max_duration)

        verify_jws_mock.assert_called_with(
            token="header.payload.sig",
            issuer_uri=self.issuer.issuer_uri,
            audience=self.issuer.audience
        )

        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]

        self.maxDiff = None
        expected_payload = {
            'action': "created",
            'object': {
                'model': 'accounts.apitoken',
                'pk': str(api_token.pk)
            }
        }

        expected_payload["object"].update({'new_value': api_token.serialize_for_event()})

        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_api_token": [str(api_token.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    def test_exchange_success_striped_name_and_default_duration(self):
        now = datetime(2026, 2, 17, 12, 0, 0)

        verify_jws_mock = Mock(return_value={
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        })

        name = get_random_string(12)

        with patch.object(token_issuers_module, "verify_jws_with_discovery", verify_jws_mock), \
             patch.object(timezone, "now", return_value=now), \
             self.captureOnCommitCallbacks(execute=True):

            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
                data={
                    "jwt": "header.payload.sig",
                    "name": f"  {name} "
                })

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["token"]["name"], name)

        api_token = APIToken.objects.get(pk=response.data["token"]["pk"])
        self.assertEqual(api_token.user_id, self.service_account.id)
        self.assertEqual(api_token.name, name)
        self.assertEqual(api_token.expiry, now + self.issuer.max_duration)

    def test_exchange_invalid_token_returns_400(self):
        with patch.object(token_issuers_module, "verify_jws_with_discovery", side_effect=Exception("bad")):
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
                data={"jwt": "x"},
            )

        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.data["detail"], "Invalid token")

    def test_exchange_cel_policy_denies(self):
        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="claims.sub == 'allow'"
        )

        verify_jws_mock = Mock(return_value={"sub": "deny"})

        with patch.object(token_issuers_module, "verify_jws_with_discovery", verify_jws_mock):
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
                data={"jwt": "x"},
            )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["detail"], "Token not allowed by policy")

    def test_exchange_invalid_cel_policy_returns_500(self):
        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="claims.sub == 'allow'"
        )

        verify_jws_mock = Mock(return_value={"sub": "abc"})

        with patch.object(token_issuers_module, "verify_jws_with_discovery", verify_jws_mock), \
             patch.object(OIDCAPITokenExchangeView, "_evaluate_cel", side_effect=Exception("cel boom")):
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
                data={"jwt": "x"},
            )

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data["detail"], "Invalid CEL policy")
