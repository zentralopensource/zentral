from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import OIDCAPITokenIssuer, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.events.base import AuditEvent


class OIDCAPITokenIssuerViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # ui user
        cls.ui_user = User.objects.create_user(get_random_string(12),
                                               "{}@zentral.io".format(get_random_string(12)),
                                               get_random_string(12),
                                               is_superuser=False)
        # ui group
        cls.ui_group = Group.objects.create(name=get_random_string(12))
        cls.ui_user.groups.set([cls.ui_group])
        # service account
        cls.service_account = User.objects.create_user(get_random_string(12),
                                                       "{}@zentral.io".format(get_random_string(12)),
                                                       is_service_account=True)

    # LoginCase implementation

    def _get_user(self):
        return self.ui_user

    def _get_group(self):
        return self.ui_group

    def _get_url_namespace(self):
        return "accounts"

    # utils

    def _force_issuer(self):
        return OIDCAPITokenIssuer.objects.create(
            audience=get_random_string(12),
            issuer_uri="https://issuer.zentral.com",
            name=get_random_string(12),
            user=self.service_account,
        )

    # user detail

    def test_user_detail_no_issuers(self):
        self.login("accounts.view_user", "accounts.view_oidcapitokenissuer")
        response = self.client.get(self.ui_user.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertNotContains(response, "OIDC API token issuer")

    def test_service_account_detail_no_perms_no_issuers(self):
        self.login("accounts.view_user")
        response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertNotContains(response, "OIDC API token issuer")

    def test_service_account_detail_view_issuers_one_link(self):
        issuer = self._force_issuer()
        self.login("accounts.view_user", "accounts.view_oidcapitokenissuer")
        response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, "OIDC API token issuer (1)")
        self.assertContains(response, issuer.name)
        self.assertNotContains(
            response,
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
        )
        self.assertContains(
            response,
            self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertNotContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertNotContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

    def test_service_account_detail_view_issuers_all_links(self):
        issuer = self._force_issuer()
        self.login(
            "accounts.add_oidcapitokenissuer",
            "accounts.change_oidcapitokenissuer",
            "accounts.delete_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
            "accounts.view_user",
        )
        response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, "OIDC API token issuer (1)")
        self.assertContains(response, issuer.name)
        self.assertContains(
            response,
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
        )
        self.assertContains(
            response,
            self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

    # create OIDC API token issuer

    def test_create_user_issuer_404(self):
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.ui_user.pk))
        self.assertEqual(response.status_code, 404)

    def test_create_issuer_login_redirect(self):
        self.login_redirect("create_oidc_api_token_issuer", self.service_account.pk)

    def test_create_issuer_permission_denied(self):
        self.login("accounts.view_user")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 403)

    def test_create_issuer_get(self):
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertContains(response, "Create OIDC API token issuer")

    def test_create_issuer_required_fields(self):
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.post(
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
            {},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertEqual(
            response.context["form"].errors,
            {'audience': ['This field is required.'],
             'issuer_uri': ['This field is required.'],
             'max_validity': ['This field is required.'],
             'name': ['This field is required.']}
        )

    def test_create_issuer_errors(self):
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.post(
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
            {"audience": get_random_string(12),
             "issuer_uri": "http://not-secure.example.com",
             "max_validity": 7,
             "cel_condition": "claims.sub ==",
             "name": get_random_string(12)},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertEqual(
            response.context["form"].errors,
            {'cel_condition': ['Invalid CEL expression.'],
             'issuer_uri': ['Must have https as scheme.'],
             'max_validity': ['Ensure this value is greater than or equal to 30.']}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_issuer(self, post_event):
        self.login(
            "accounts.add_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
        )
        name = get_random_string(12)
        audience = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
                {"audience": audience,
                 "issuer_uri": "https://accounts.google.com",
                 "max_validity": 600,
                 "cel_condition": "claims.sub == 'yolo'",
                 "name": name},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, "https://accounts.google.com")
        issuer = OIDCAPITokenIssuer.objects.get(user=self.service_account, name=name)
        self.assertEqual(issuer.audience, audience)
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "accounts.oidcapitokenissuer",
                 "pk": str(issuer.pk),
                 "new_value": {
                     "audience": audience,
                     "cel_condition": "claims.sub == 'yolo'",
                     "created_at": issuer.created_at.isoformat(),
                     "issuer_uri": "https://accounts.google.com",
                     "max_validity": 600,
                     "name": name,
                     "pk": str(issuer.pk),
                     "updated_at": issuer.updated_at.isoformat(),
                     "user": {
                         "email": self.service_account.email,
                         "pk": self.service_account.pk,
                         "username": self.service_account.username,
                     }
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    # view OIDC API token issuer

    def test_view_issuer_login_redirect(self):
        issuer = self._force_issuer()
        self.login_redirect("oidc_api_token_issuer", self.service_account.pk, issuer.pk)

    def test_view_issuer_permission_denied(self):
        issuer = self._force_issuer()
        self.login("accounts.view_user")
        response = self.client.get(self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 403)

    def test_view_issuer_get_no_links(self):
        issuer = self._force_issuer()
        self.login("accounts.view_oidcapitokenissuer")
        response = self.client.get(self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_detail.html")
        self.assertContains(response, issuer.name)
        self.assertNotContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertNotContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

    def test_view_issuer_get_all_links(self):
        issuer = self._force_issuer()
        self.login(
            "accounts.change_oidcapitokenissuer",
            "accounts.delete_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
        )
        response = self.client.get(self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_detail.html")
        self.assertContains(response, issuer.name)
        self.assertContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

    # update OIDC API token issuer

    def test_update_issuer_login_redirect(self):
        issuer = self._force_issuer()
        self.login_redirect("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk)

    def test_update_issuer_permission_denied(self):
        issuer = self._force_issuer()
        self.login("accounts.view_user")
        response = self.client.get(self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 403)

    def test_update_issuer_permission_get(self):
        issuer = self._force_issuer()
        self.login("accounts.change_oidcapitokenissuer")
        response = self.client.get(self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertContains(response, "Update OIDC API token issuer")

    @patch("accounts.forms.get_openid_configuration_from_issuer_uri")
    def test_update_issuer_issuer_oid_config_error(self, get_openid_configuration_from_issuer_uri):
        get_openid_configuration_from_issuer_uri.side_effect = Exception("Boom!")
        issuer = self._force_issuer()
        self.login(
            "accounts.change_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
        )
        name = get_random_string(12)
        audience = get_random_string(12)
        response = self.client.post(
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
            {"audience": audience,
             "issuer_uri": "https://issuer.zentral.com",
             "max_validity": 600,
             "cel_condition": "claims.sub == 'yolo'",
             "name": name},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertEqual(
            response.context["form"].errors,
            {'issuer_uri': ['Could not find valid OpenID configuration']},
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_issuer(self, post_event):
        issuer = self._force_issuer()
        prev_value = issuer.serialize_for_event()
        self.login(
            "accounts.change_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
        )
        name = get_random_string(12)
        audience = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
                {"audience": audience,
                 "issuer_uri": "https://accounts.google.com",
                 "max_validity": 600,
                 "cel_condition": "claims.sub == 'yolo'",
                 "name": name},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, "https://accounts.google.com")
        issuer2 = OIDCAPITokenIssuer.objects.get(user=self.service_account, name=name)
        self.assertEqual(issuer2, issuer)
        self.assertEqual(issuer2.name, name)
        self.assertEqual(issuer2.audience, audience)
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "accounts.oidcapitokenissuer",
                 "pk": str(issuer.pk),
                 "prev_value": prev_value,
                 "new_value": {
                     "audience": audience,
                     "cel_condition": "claims.sub == 'yolo'",
                     "created_at": issuer2.created_at.isoformat(),
                     "issuer_uri": "https://accounts.google.com",
                     "max_validity": 600,
                     "name": name,
                     "pk": str(issuer.pk),
                     "updated_at": issuer2.updated_at.isoformat(),
                     "user": {
                         "email": self.service_account.email,
                         "pk": self.service_account.pk,
                         "username": self.service_account.username,
                     }
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    # delete OIDC API token issuer

    def test_delete_issuer_login_redirect(self):
        issuer = self._force_issuer()
        self.login_redirect("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk)

    def test_delete_issuer_permission_denied(self):
        issuer = self._force_issuer()
        self.login("accounts.view_user")
        response = self.client.get(self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 403)

    def test_delete_issuer_permission_get(self):
        issuer = self._force_issuer()
        self.login("accounts.delete_oidcapitokenissuer")
        response = self.client.get(self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_confirm_delete.html")
        self.assertContains(response, "Delete OIDC API token issuer")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_issuer(self, post_event):
        issuer = self._force_issuer()
        prev_value = issuer.serialize_for_event()
        self.login(
            "accounts.delete_oidcapitokenissuer",
            "accounts.view_user",
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, self.service_account.username)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(pk=issuer.pk).exists())
        # AuditEvent
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "accounts.oidcapitokenissuer",
                 "pk": str(issuer.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_oidc_api_token_issuer": [str(issuer.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
