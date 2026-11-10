from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

import requests

from accounts.models import APIToken, OIDCAPITokenIssuer, User
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework import serializers

from tests.server_accounts.utils import GOOGLE_OPENID_CONFIGURATION
from tests.zentral_test_utils.zentral_api_test_case import ZentralAPITestCase
from zentral.core.events.base import AuditEvent


class OIDCAPITokenExchangeViewTestCase(ZentralAPITestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()

        # issuer
        cls.issuer = cls._create_token_issuer(user=cls.service_account)

    @staticmethod
    def _create_token_issuer(
            user: User,
            cel_condition: str = "claims.sub == 'abc'",
            description: str = "",
            max_validity: int = 60,
    ):
        return OIDCAPITokenIssuer.objects.create(
            user=user,
            name=get_random_string(12),
            description=description,
            issuer_uri="https://accounts.google.com",
            audience=f"aud-{get_random_string(10)}",
            cel_condition=cel_condition,
            max_validity=max_validity,
        )

    # OIDC API token auth

    @patch("requests.Session.get")
    def test_auth_errors(self, requests_get):
        requests_get.return_value.json.return_value = GOOGLE_OPENID_CONFIGURATION
        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
            data={"jwt": "yolo", "validity": self.issuer.max_validity * 2},
            include_token=False,
        )
        self.assertEqual(
            response.json(),
            {"jwt": ["Invalid token"],
             "validity": ["Must be ≤ 60s"]},
        )

    @patch("requests.Session.get")
    def test_auth_discovery_errors(self, requests_get):
        for side_effect, status_code in ((requests.Timeout("Boom!!!"), None),
                                         (requests.ConnectionError("Boom!!!"), None)):
            requests_get.reset_mock()
            requests_get.side_effect = side_effect
            requests_get.return_value.status_code = status_code
            requests_get.return_value.json.return_value = GOOGLE_OPENID_CONFIGURATION
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
                data={"jwt": "yolo"},
                include_token=False,
            )
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json(), {"jwt": ["Could not get the OpenID configuration"]})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_success(self, tznow, verify_jws_with_discovery, post_event):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
                data={
                    "jwt": "header.payload.sig",
                    "name": "yolo",
                    "validity": self.issuer.max_validity / 2
                },
                include_token=False,
            )

        self.assertEqual(response.status_code, 200, response.data)
        resp_json = response.json()
        secret = resp_json.pop("secret")
        self.assertTrue(secret.startswith("ztls_"))
        api_token = APIToken.objects.get(pk=resp_json["id"])
        self.assertEqual(
            resp_json,
            {'expiry': '2026-02-17T12:00:30',
             'id': str(api_token.pk),
             'name': 'yolo',
             'user': {'email': self.service_account.email,
                      'id': self.service_account.pk,
                      'is_service_account': True,
                      'username': self.service_account.username}}
        )

        verify_jws_with_discovery.assert_called_with(
            token="header.payload.sig",
            issuer_uri=self.issuer.issuer_uri,
            audience=self.issuer.audience,
            exception_class=serializers.ValidationError,
        )

        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                'action': "created",
                'object': {
                    'model': 'accounts.apitoken',
                    'pk': str(api_token.pk),
                    'new_value': api_token.serialize_for_event(),
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_api_token": [str(api_token.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_success_striped_name_and_default_validity(self, tznow, verify_jws_with_discovery):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        }

        name = get_random_string(12)

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(self.issuer.pk,)),
            data={
                "jwt": "header.payload.sig",
                "name": f"  {name} ",
            },
            include_token=False,
        )

        self.assertEqual(response.status_code, 200, response.data)
        self.assertEqual(response.data["name"], name)

        api_token = APIToken.objects.get(pk=response.json()["id"])
        self.assertEqual(api_token.user_id, self.service_account.id)
        self.assertEqual(api_token.name, name)
        self.assertEqual(api_token.expiry, datetime(2026, 2, 17, 12, 1, 0))

    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_success_with_cel_condition(self, tznow, verify_jws_with_discovery):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
            "sub": "bingo!",
        }

        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="claims.sub == 'bingo!'",
            max_validity=3600,
        )

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
            data={"jwt": "header.payload.sig"},
            include_token=False,
        )

        self.assertEqual(response.status_code, 200, response.data)

        api_token = APIToken.objects.get(pk=response.json()["id"])
        self.assertEqual(api_token.user_id, self.service_account.id)
        self.assertEqual(api_token.expiry, datetime(2026, 2, 17, 13, 0, 0))

    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_cel_condition_error(self, tznow, verify_jws_with_discovery):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        }

        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="claims.sub == 'allow'",
            max_validity=3600,
        )
        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
            data={"jwt": "header.payload.sig"},
            include_token=False,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'jwt': ['Invalid token claims']})

    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_cel_condition_evaluation_error(self, tznow, verify_jws_with_discovery):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        }

        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="claims.sub ==",  # should not be allowed in the first place
            max_validity=3600,
        )
        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
            data={"jwt": "header.payload.sig"},
            include_token=False,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'jwt': ['Unexpected error during CEL condition evaluation']})

    @patch("accounts.serializers.verify_jws_with_discovery")
    @patch("accounts.serializers.timezone.now")
    def test_auth_cel_condition_evaluation_not_a_boolean(self, tznow, verify_jws_with_discovery):
        now = datetime(2026, 2, 17, 12, 0, 0)
        tznow.return_value = now

        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": self.issuer.issuer_uri,
            "aud": self.issuer.audience,
        }

        issuer = self._create_token_issuer(
            user=self.service_account,
            cel_condition="'hello'",  # not a bool
            max_validity=3600,
        )
        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
            data={"jwt": "header.payload.sig"},
            include_token=False,
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json(), {'jwt': ["CEL condition evaluation didn't produce a boolean"]})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("accounts.serializers.verify_jws_with_discovery")
    def test_auth_issuer_of_a_superuser(self, verify_jws_with_discovery, post_event):
        user = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io")
        issuer = self._create_token_issuer(user)
        # old data: the console gives an issuer to a service account only
        User.objects.filter(pk=user.pk).update(is_superuser=True)
        verify_jws_with_discovery.return_value = {"sub": "abc", "iss": issuer.issuer_uri, "aud": issuer.audience}
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            with self.assertLogs("server.accounts.serializer", level="ERROR") as cm:
                response = self.post(
                    url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
                    data={"jwt": "header.payload.sig"},
                    include_token=False,
                )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.json(), {"jwt": ["The user of the issuer cannot have an API token"]})
        self.assertEqual(cm.output, [f"ERROR:server.accounts.serializer:"
                                     f"The user of the issuer cannot have an API token {issuer.pk}"])
        self.assertFalse(APIToken.objects.filter(user=user).exists())
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    # mandatory CEL condition

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("accounts.serializers.verify_jws_with_discovery")
    def test_auth_issuer_without_cel_condition(self, verify_jws_with_discovery, post_event):
        """Refused, instead of accepting every token the provider signs for the audience."""
        issuer = self._create_token_issuer(self.service_account, cel_condition="")
        verify_jws_with_discovery.return_value = {
            "sub": "abc",
            "iss": issuer.issuer_uri,
            "aud": issuer.audience,
        }
        # this service account already owns the test case's own token
        token_count = APIToken.objects.filter(user=self.service_account).count()
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuer_exchange", args=(issuer.pk,)),
                data={"jwt": "header.payload.sig"},
                include_token=False,
            )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(response.json(), {"jwt": ["The issuer has no CEL condition"]})
        self.assertEqual(APIToken.objects.filter(user=self.service_account).count(), token_count)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    # list OIDC API token issuers

    def test_list_token_issuers_unauthorized(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuers"), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_list_token_issuers_forbidden(self):
        response = self.get(reverse("accounts_api:oidc_api_token_issuers"))
        self.assertEqual(response.status_code, 403, response.data)

    def test_list_token_issuers(self):
        self.set_permissions("accounts.view_oidcapitokenissuer")
        second_issuer = self._create_token_issuer(self.service_account)
        response = self.get(url=reverse("accounts_api:oidc_api_token_issuers"))
        self.assertEqual(response.status_code, 200, response.data)
        issuers_page = response.json()
        self.assertEqual(2, issuers_page["count"])
        self.assertEqual(str(second_issuer.id), issuers_page["results"][0]["id"])  # ordered by -created_at
        self.assertEqual(str(self.issuer.id), issuers_page["results"][1]["id"])

    def test_list_token_issuers_name_filter(self):
        self.set_permissions("accounts.view_oidcapitokenissuer")
        self._create_token_issuer(self.service_account)
        response = self.get(url=reverse("accounts_api:oidc_api_token_issuers") + f"?name={self.issuer.name}")
        self.assertEqual(response.status_code, 200, response.data)
        issuers_page = response.json()
        self.assertEqual(1, issuers_page["count"])  # only one
        self.assertEqual(str(self.issuer.id), issuers_page["results"][0]["id"])

    # create OIDC API token issuer

    def test_create_token_issuer_forbidden(self):
        # the permission check comes before the method check
        response = self.post(url=reverse("accounts_api:oidc_api_token_issuers"), data={})
        self.assertEqual(response.status_code, 403, response.data)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_token_issuer_method_not_allowed(self, post_event):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": get_random_string(12),
            "issuer_uri": "https://accounts.google.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "claims.sub == 'abc'",
            "max_validity": 60,
        }
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(url=reverse("accounts_api:oidc_api_token_issuers"), data=payload)
        self.assertEqual(response.status_code, 405, response.data)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(name=payload["name"]).exists())
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    # get OIDC API token issuer

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

    # update OIDC API token issuer

    def test_update_token_issuer_unauthorized(self):
        response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)),
                            {},
                            include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_update_token_issuer_forbidden(self):
        response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), {})
        self.assertEqual(response.status_code, 403, response.data)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_token_issuer_method_not_allowed(self, post_event):
        self.set_permissions("accounts.change_oidcapitokenissuer")
        payload = {
            "user": self.service_account.pk,
            "name": self.issuer.name,
            "issuer_uri": self.issuer.issuer_uri,
            "audience": self.issuer.audience,
            "cel_condition": self.issuer.cel_condition,
            "description": "updated desc"
        }
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), payload)
        self.assertEqual(response.status_code, 405, response.data)
        self.issuer.refresh_from_db()
        self.assertEqual(self.issuer.description, "")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    # delete OIDC API token issuer

    def test_token_issuer_delete_unauthorized(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_token_issuer_delete_forbidden(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)))
        self.assertEqual(response.status_code, 403, response.data)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_token_issuer_method_not_allowed(self, post_event):
        self.set_permissions("accounts.delete_oidcapitokenissuer")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)))
        self.assertEqual(response.status_code, 405, response.data)
        self.assertTrue(OIDCAPITokenIssuer.objects.filter(pk=self.issuer.pk).exists())
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)
