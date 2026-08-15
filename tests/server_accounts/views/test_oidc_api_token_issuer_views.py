from unittest.mock import patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import OIDCAPITokenIssuer, Policy, User
from pbac.engine import engine
from pbac.entities import Entity
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
            cel_condition="claims.sub == 'existing'",
            issuer_uri="https://issuer.zentral.com",
            name=get_random_string(12),
            user=self.service_account,
        )

    def _put_service_account_out_of_reach(self):
        """Give the service account a role the UI user doesn't have."""
        group = Group.objects.create(name=get_random_string(12))
        self.service_account.groups.add(group)
        return group

    def _promote_ui_user_to_superuser(self):
        self.ui_user.is_superuser = True
        self.ui_user.save()

    def _issuer_form_payload(self):
        return {"audience": get_random_string(12),
                "cel_condition": "claims.sub == 'yolo'",
                "issuer_uri": "https://accounts.google.com",
                "max_validity": 600,
                "name": get_random_string(12)}

    def _force_policy_naming_service_account(self, is_active=True):
        # separate policy: set_policy() overwrites the one carrying the perms
        return Policy.objects.create(
            name=get_random_string(12),
            is_active=is_active,
            source=(
                'permit (\n'
                f'  principal == {Entity("ServiceAccount", str(self.service_account.pk))},\n'
                f'  action in [{engine.legacy_perm_actions["accounts.view_user"]}],\n'
                '  resource\n'
                ');'
            ),
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
             'cel_condition': ['This field is required.'],
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

    # mandatory CEL condition

    def test_create_issuer_blank_cel_condition(self):
        self.login("accounts.add_oidcapitokenissuer")
        payload = self._issuer_form_payload()
        payload["cel_condition"] = ""
        response = self.client.post(
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
            payload,
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/oidcapitokenissuer_form.html")
        self.assertEqual(
            response.context["form"].errors,
            {"cel_condition": ["This field is required."]},
        )
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(user=self.service_account).exists())

    def test_update_issuer_blank_cel_condition(self):
        """The condition cannot be dropped from an existing issuer."""
        issuer = self._force_issuer()
        self.login("accounts.change_oidcapitokenissuer")
        payload = self._issuer_form_payload()
        payload["cel_condition"] = ""
        response = self.client.post(
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
            payload,
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["form"].errors,
            {"cel_condition": ["This field is required."]},
        )
        issuer.refresh_from_db()
        self.assertEqual(issuer.cel_condition, "claims.sub == 'existing'")

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

    # role boundary

    def test_create_issuer_service_account_with_ungrantable_role_permission_denied(self):
        self._put_service_account_out_of_reach()
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 403)

    def test_create_issuer_service_account_with_ungrantable_role_post_permission_denied(self):
        self._put_service_account_out_of_reach()
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.post(
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
            self._issuer_form_payload(),
        )
        self.assertEqual(response.status_code, 403)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(user=self.service_account).exists())

    def test_create_issuer_service_account_with_shared_role(self):
        self.service_account.groups.add(self.ui_group)
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 200)

    def test_create_issuer_service_account_with_ungrantable_role_superuser(self):
        self._put_service_account_out_of_reach()
        self._promote_ui_user_to_superuser()
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 200)

    def test_create_issuer_service_account_named_by_policy_permission_denied(self):
        # its privileges no longer follow from its roles
        self._force_policy_naming_service_account()
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 403)

    def test_create_issuer_service_account_named_by_inactive_policy_permission_denied(self):
        # a disabled grant is one superuser away from being live
        self._force_policy_naming_service_account(is_active=False)
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 403)

    def test_create_issuer_service_account_named_by_policy_superuser(self):
        self._force_policy_naming_service_account()
        self._promote_ui_user_to_superuser()
        self.login("accounts.add_oidcapitokenissuer")
        response = self.client.get(self.build_url("create_oidc_api_token_issuer", self.service_account.pk))
        self.assertEqual(response.status_code, 200)

    def test_update_issuer_service_account_with_ungrantable_role_permission_denied(self):
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login("accounts.change_oidcapitokenissuer")
        response = self.client.get(self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 403)

    def test_update_issuer_service_account_with_ungrantable_role_post_permission_denied(self):
        # repointing at a provider the requester controls is the escalation
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login("accounts.change_oidcapitokenissuer")
        response = self.client.post(
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
            self._issuer_form_payload(),
        )
        self.assertEqual(response.status_code, 403)
        issuer.refresh_from_db()
        self.assertEqual(issuer.issuer_uri, "https://issuer.zentral.com")

    def test_view_issuer_service_account_with_ungrantable_role_allowed(self):
        # reading an issuer grants nothing
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login("accounts.view_oidcapitokenissuer")
        response = self.client.get(self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)

    def test_delete_issuer_service_account_with_ungrantable_role_allowed(self):
        # revoking is not escalating
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login("accounts.delete_oidcapitokenissuer", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(OIDCAPITokenIssuer.objects.filter(pk=issuer.pk).exists())

    def test_service_account_detail_hides_write_links_when_out_of_reach(self):
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login(
            "accounts.add_oidcapitokenissuer",
            "accounts.change_oidcapitokenissuer",
            "accounts.delete_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
            "accounts.view_user",
        )
        response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(
            response,
            self.build_url("create_oidc_api_token_issuer", self.service_account.pk),
        )
        self.assertNotContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

    def test_view_issuer_hides_update_link_when_out_of_reach(self):
        issuer = self._force_issuer()
        self._put_service_account_out_of_reach()
        self.login(
            "accounts.change_oidcapitokenissuer",
            "accounts.delete_oidcapitokenissuer",
            "accounts.view_oidcapitokenissuer",
        )
        response = self.client.get(self.build_url("oidc_api_token_issuer", self.service_account.pk, issuer.pk))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(
            response,
            self.build_url("update_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )
        self.assertContains(
            response,
            self.build_url("delete_oidc_api_token_issuer", self.service_account.pk, issuer.pk),
        )

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
