from datetime import datetime
from unittest.mock import patch
from uuid import uuid4

from accounts.models import APIToken, OIDCAPITokenIssuer, User
from django.urls import reverse
from django.utils.crypto import get_random_string
from rest_framework import serializers

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
            cel_condition: str = "",
            description: str = "",
            max_validity: int = 60,
    ):
        return OIDCAPITokenIssuer.objects.create(
            user=user,
            name=get_random_string(12),
            description=description,
            issuer_uri="https://accounts.google.com",  # TODO mock instead of making a real HTTP request?
            audience=f"aud-{get_random_string(10)}",
            cel_condition=cel_condition,
            max_validity=max_validity,
        )

    # OIDC API token auth

    def test_auth_errors(self):
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

    def test_create_token_issuer_validation_errors(self):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        payload = {
            "user": self.user.pk,
            "name": get_random_string(12),
            "description": "",
            "issuer_uri": "http://issuer.example.com",
            "audience": f"aud-{get_random_string(10)}",
            "cel_condition": "claims.sub ==",
            "max_validity": 60,
        }

        response = self.post(
            url=reverse("accounts_api:oidc_api_token_issuers"),
            data=payload,
        )
        self.assertEqual(response.status_code, 400, response.data)
        self.assertEqual(
            response.json(),
            {'cel_condition': ['Invalid CEL expression.'],
             'issuer_uri': ['Must have https as scheme.'],
             'user': ['User must be a service account.']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_token_issuer(self, post_event):
        self.set_permissions("accounts.add_oidcapitokenissuer")
        name = get_random_string(12)
        payload = {
            "user": self.service_account.pk,
            "name": name,
            "description": "description",
            "issuer_uri": "https://accounts.google.com",
            "audience": "audience",
            "cel_condition": "claims.sub == 'abc'",
            "max_validity": 60,
        }

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.post(
                url=reverse("accounts_api:oidc_api_token_issuers"),
                data=payload,
            )
        self.assertEqual(response.status_code, 201)
        issuer = OIDCAPITokenIssuer.objects.get(name=name)
        self.assertEqual(
            response.json(),
            {'audience': 'audience',
             'cel_condition': "claims.sub == 'abc'",
             'created_at': issuer.created_at.isoformat(),
             'description': 'description',
             'id': str(issuer.pk),
             'issuer_uri': 'https://accounts.google.com',
             'max_validity': 60,
             'name': name,
             'updated_at': issuer.updated_at.isoformat(),
             'user': self.service_account.pk}
        )
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {'model': 'accounts.oidcapitokenissuer',
                        'pk': str(issuer.pk),
                        'new_value': issuer.serialize_for_event()}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

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
    def test_update_token_issuer(self, post_event):
        self.set_permissions("accounts.change_oidcapitokenissuer")
        prev_value = self.issuer.serialize_for_event()
        payload = {
            "user": self.service_account.pk,
            "name": self.issuer.name,
            "issuer_uri": self.issuer.issuer_uri,
            "audience": self.issuer.audience,
            "description": "updated desc"
        }
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.put(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)), payload)
        self.assertEqual(response.status_code, 200, response.data)
        self.issuer.refresh_from_db()
        self.assertEqual(self.issuer.description, "updated desc")
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'updated',
             'object': {'model': 'accounts.oidcapitokenissuer',
                        'pk': str(self.issuer.pk),
                        'prev_value': prev_value,
                        'new_value': self.issuer.serialize_for_event()}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(self.issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    # delete OIDC API token issuer

    def test_token_issuer_delete_unauthorized(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)), include_token=False)
        self.assertEqual(response.status_code, 401, response.data)

    def test_token_issuer_delete_forbidden(self):
        response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(uuid4(),)))
        self.assertEqual(response.status_code, 403, response.data)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_issuer(self, post_event):
        self.set_permissions("accounts.delete_oidcapitokenissuer")
        issuer = self._create_token_issuer(
            self.service_account,
            cel_condition="claims.sub == 'abc'",
            description="description",
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.delete(reverse("accounts_api:oidc_api_token_issuer", args=(issuer.pk,)))
        self.assertEqual(response.status_code, 204, response.data)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(pk=issuer.pk).exists())
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'deleted',
             'object': {'model': 'accounts.oidcapitokenissuer',
                        'pk': str(issuer.pk),
                        'prev_value': {'audience': issuer.audience,
                                       'cel_condition': "claims.sub == 'abc'",
                                       'created_at': issuer.created_at.isoformat(),
                                       'description': 'description',
                                       'issuer_uri': 'https://accounts.google.com',
                                       'max_validity': 60,
                                       'name': issuer.name,
                                       'pk': str(issuer.pk),
                                       'updated_at': issuer.updated_at.isoformat(),
                                       'user': {'email': self.service_account.email,
                                                'pk': self.service_account.pk,
                                                'username': self.service_account.username}}}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
