from datetime import datetime, timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

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
            issuer_uri="https://issuer.zentral.com",
            audience=f"aud-{get_random_string(10)}",
            cel_condition=cel_condition,
            max_duration=timedelta(seconds=60),
        )

    def post(self, url, data=None, include_token=False):
        return super().post(url=url, data=data, include_token=include_token)

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

    # OIDCAPITokenIssuerViewList

    def test_list_token_issuers_unauthorized(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuers"), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_list_token_issuers_forbidden(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuers"))
        self.assertEqual(response.status_code, 403, response.data)

    def test_list_token_issuers(self):
        self.set_permissions("accounts.view_oidcapitokenissuer")
        response = self.get(url=reverse("accounts_api:oidc_api_token_issuers"))
        self.assertEqual(response.status_code, 200, response.data)
        issuers_page = response.json()
        self.assertEqual(1, issuers_page["count"])
        self.assertEqual(str(self.issuer.id), issuers_page["results"][0]["id"])

    def test_create_issuer_success_admin_sets_user(self):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": get_random_string(12),
            "description": "",
            "issuer_uri": "https://issuer.zentral.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "",
            "max_duration": "00:01:00"
        }

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuers"), 
            data=payload,
            include_token=True)
        self.assertEqual(response.status_code, 201)

        created_id = response.data["id"]
        issuer = OIDCAPITokenIssuer.objects.get(pk=created_id)
        self.assertEqual(issuer.name, payload["name"])

    def test_create_issuer_with_valid_cel_condition(self):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": get_random_string(12),
            "description": "",
            "issuer_uri": "https://issuer.zentral.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "claims.sub == 'abc'",
            "max_duration": "00:01:00"
        }

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuers"), 
            data=payload,
            include_token=True)

        self.assertIn(response.status_code, (200, 201), response.data)
        self.assertEqual(response.data.get("cel_condition"), "claims.sub == 'abc'")

    def test_create_triggers_https_url_validator(self):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": get_random_string(12),
            "description": "",
            "issuer_uri": "http://issuer.example.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "",
            "max_duration": "00:01:00",
        }

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuers"),
            data=payload,
            include_token=True)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn("issuer_uri", response.data)

    def test_update_triggers_https_cel_validator(self):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": get_random_string(12),
            "description": "",
            "issuer_uri": "https://issuer.example.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "claims.sub ==",
            "max_duration": "00:01:00",
        }

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuers"),
            data=payload,
            include_token=True)
        self.assertEqual(response.status_code, 400, response.data)
        self.assertIn("cel_condition", response.data)

    # OIDCAPITokenIssuerViewDetail

    def test_token_issuer_unauthorized(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_token_issuer_forbidden(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)))
        self.assertEqual(response.status_code, 403, response.data)

    def test_token_issuer(self):
        self.set_permissions("accounts.view_oidcapitokenissuer")
        response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)))
        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["id"], str(self.issuer.pk))

    def test_token_issuer_update_unauthorized(self):
        response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)),
                            {},
                            include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_token_issuer_update_forbidden(self):
        response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), {})
        self.assertEqual(response.status_code, 403, response.data)

    def test_token_issuer_update(self):
        self.set_permissions("accounts.change_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": self.issuer.name,
            "issuer_uri": self.issuer.issuer_uri,
            "audience": self.issuer.audience,
            "description": "updated desc"
        }
        response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), payload)
        self.assertEqual(response.status_code, 200, response.data)

        self.issuer.refresh_from_db()
        self.assertEqual(self.issuer.description, "updated desc")

    def test_token_issuer_delete_unauthorized(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_token_issuer_delete_forbidden(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)))
        self.assertEqual(response.status_code, 403, response.data)

    def test_delete_issuer(self):
        self.set_permissions("accounts.delete_oidcapitokenissuer")
        issuer = self._create_token_issuer(self.service_account)

        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(issuer.pk,)))
        self.assertEqual(response.status_code, 204, response.data)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(pk=issuer.pk).exists())
