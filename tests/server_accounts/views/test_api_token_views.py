import uuid
from datetime import datetime, timedelta
from unittest.mock import patch

from accounts.models import APIToken, User
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from tests.server_accounts.utils import force_user_token
from tests.zentral_test_utils.assertions.event_assertions import EventAssertions
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.events.base import AuditEvent


class APITokenViewsTestCase(TestCase, LoginCase, EventAssertions):
    @classmethod
    def setUpTestData(cls):
        # ui user
        cls.ui_user_pwd = get_random_string(12)
        cls.ui_user = User.objects.create_user(get_random_string(12),
                                               "{}@zentral.io".format(get_random_string(12)),
                                               cls.ui_user_pwd,
                                               is_superuser=False)

        # group
        cls.ui_group = Group.objects.create(name=get_random_string(12))
        cls.ui_user.groups.set([cls.ui_group])

        # user
        cls.user = User.objects.create_user(get_random_string(19),
                                            "{}@zentral.io".format(get_random_string(12)),
                                            get_random_string(18))

        # service account
        cls.service_account = User.objects.create_user(get_random_string(19),
                                                       "{}@zentral.io".format(get_random_string(12)),
                                                       get_random_string(12),
                                                       is_service_account=True)

    # LoginCase implementation

    def _get_user(self):
        return self.ui_user

    def _get_group(self):
        return self.ui_group

    def _get_url_namespace(self):
        return "accounts"

    # create API token

    def test_create_api_token_login_redirect(self):
        """User is not logged in."""
        self.permission_denied("create_user_api_token", self.user.id)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_api_token_not_self(self, post_event):
        """User can not create token for other users (ui_user != user)"""
        self.login()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(self.user.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_api_token_no_perms(self, post_event):
        """User can not create token for a service account without the permissions."""
        self.login()

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(self.service_account.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def test_create_api_token_not_allowed(self):
        """User is not allowed to create token for other user, only for service account."""
        other_user = User.objects.create_user(get_random_string(19), "{}@zentral.io".format(get_random_string(12)),
                                              get_random_string(12), is_service_account=False)
        self.login("accounts.view_user", "accounts.add_apitoken")

        response = self.client.post(
                reverse("accounts:create_user_api_token", args=(other_user.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertRaises(PermissionDenied, msg="Not allowed")

    def test_create_api_token_allowed_self(self):
        """Users are allowed to create token for themselves."""
        self.login()
        response = self.client.post(
                reverse("accounts:create_user_api_token", args=(self.ui_user.id,)), follow=True)
        self.assertEqual(response.status_code, 200)

    def test_create_api_token_form(self):
        """User can create token for a service account with the required permissions."""
        self.login("accounts.view_user", "accounts.add_apitoken")

        response = self.client.get(
                reverse("accounts:create_user_api_token", args=(self.service_account.id,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create API token")
        self.assertContains(response, "Give your API token a descriptive name.")
        self.assertEqual(response.context['title'], 'Create API token')
        self.assertEqual(response.context['breadcrumb_title'], 'API token')
        self.assertEqual(response.context['user'], self.service_account)

        expired_date = datetime.today() - timedelta(days=1)
        token_name = "totoken"
        response = self.client.post(reverse("accounts:create_user_api_token", args=(self.service_account.id,)),
                                    {"name": token_name, "expiry": expired_date}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The expiration date must be in the future.")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_self_create_api_token(self, post_event):
        """Users can create token for themselves without the required permissions."""
        self.login()
        expiry_date = datetime.today() + timedelta(days=1)
        token_name = "totoken"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:create_user_api_token", args=(self.ui_user.id,)),
                                        {"name": token_name, "expiry": expiry_date}, follow=True)
        user = response.context["object"]
        api_key = response.context["api_key"]
        api_token = user.apitoken_set.first()

        self.assertTemplateUsed(response, "accounts/user_api_token.html")
        self.assertEqual(user, self.ui_user)
        self.assertContains(response, "Settings")
        self.assertContains(response, api_key)
        self.assertEqual(APIToken.objects._hash_key(api_key), api_token.hashed_key)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            {"action": "created",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(api_token.pk),
                 "new_value": {
                     "pk": api_token.pk,
                     "name": token_name,
                     "user": self.ui_user.serialize_for_event(),
                     "expiry": expiry_date,
                     "created_at": api_token.created_at,
                     "hashed_key": api_token.hashed_key
                 }
              }},
            {"accounts_api_token": [str(api_token.pk)]},
            post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_create_api_token(self, post_event):
        """Users can create token for a service account with the required permissions."""
        self.login("accounts.view_user", "accounts.add_apitoken")

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(self.service_account.id,)), follow=True)
        user = response.context["object"]
        api_key = response.context["api_key"]
        api_token = user.apitoken_set.first()

        self.assertEqual(user, self.service_account)
        self.assertTemplateUsed(response, "accounts/user_api_token.html")
        self.assertNotContains(response, "Settings")
        self.assertContains(response, "Users")
        self.assertEqual(APIToken.objects._hash_key(api_key), self.service_account.apitoken_set.first().hashed_key)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            {"action": "created",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(api_token.pk),
                 "new_value": {
                     "pk": api_token.pk,
                     "name": api_token.name,
                     "user": user.serialize_for_event(),
                     "expiry": api_token.expiry,
                     "created_at": api_token.created_at,
                     "hashed_key": api_token.hashed_key
                 }
              }},
            {"accounts_api_token": [str(api_token.pk)]},
            post_event)

    # update API token

    def test_update_apitoken_redirect(self):
        """User can not call the route without login."""
        user, token = force_user_token()
        self.permission_denied("update_user_api_token", user.id, token.id)

    def test_update_apitoken_permission_denied(self):
        """User can not update token from other users (ui_user != user)."""
        self.login()
        user, token = force_user_token()
        response = self.client.post(reverse("accounts:update_user_api_token", args=(user.id, token.id)), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_update_api_token_no_perms(self):
        """User can not update token for a service account without the permissions."""
        self.login()

        _, token = force_user_token(user=self.service_account)
        # service account OK, but without the required permissions
        response = self.client.post(reverse("accounts:update_user_api_token",
                                            args=(self.service_account.id, token.id)), follow=True)
        self.assertEqual(response.status_code, 403)

    def test_update_apitoken_get(self):
        """Get form to update own token."""
        self.login()
        _, token = force_user_token(self.ui_user)
        response = self.client.get(reverse("accounts:update_user_api_token", args=(self.ui_user.id, token.id)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/token_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_apitoken_serviceaccount_ok(self, post_event):
        """Update service account token with required permissions set."""
        self.login("accounts.change_apitoken", "accounts.view_user",)
        expiry_date = datetime.today() + timedelta(days=1)
        expiry_date_new = datetime.today() + timedelta(days=2)
        token_name = "oldtoken"
        new_token_name = "newtoken"
        _, token = force_user_token(self.service_account, name=token_name, expiry=expiry_date)

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user_api_token", args=(self.service_account.id, token.id)),
                {"name": new_token_name, "expiry": expiry_date_new},
                follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_detail.html")

        api_token = APIToken.objects.get(id=token.id)
        self.assertEqual(api_token.name, new_token_name)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            {"action": "updated",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(api_token.pk),
                 "new_value": {
                     "pk": api_token.pk,
                     "name": new_token_name,
                     "user": self.service_account.serialize_for_event(),
                     "expiry": expiry_date_new,
                     "created_at": api_token.created_at,
                     "hashed_key": api_token.hashed_key
                 },
                 "prev_value": token.serialize_for_event()
              }},
            {"accounts_api_token": [str(api_token.pk)]},
            post_event)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_apitoken_self_ok(self, post_event):
        """Update own user token without permissions."""
        self.login()
        expiry_date = datetime.today() + timedelta(days=1)
        expiry_date_new = datetime.today() + timedelta(days=2)
        token_name = "oldtoken"
        new_token_name = "newtoken"
        _, token = force_user_token(self.ui_user, name=token_name, expiry=expiry_date)

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user_api_token", args=(self.ui_user.id, token.id)),
                {"name": new_token_name, "expiry": expiry_date_new},
                follow=True)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/profile.html")

        api_token = APIToken.objects.get(id=token.id)
        self.assertEqual(api_token.name, new_token_name)

        self.assert_events_published(1, callbacks, post_event)
        self.assert_is_audit_event(
            {"action": "updated",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(api_token.pk),
                 "new_value": {
                     "pk": api_token.pk,
                     "name": new_token_name,
                     "user": self.ui_user.serialize_for_event(),
                     "expiry": expiry_date_new,
                     "created_at": api_token.created_at,
                     "hashed_key": api_token.hashed_key
                 },
                 "prev_value": token.serialize_for_event()
              }},
            {"accounts_api_token": [str(api_token.pk)]},
            post_event)

    # delete API token

    def test_delete_apitoken_redirect(self):
        """User can not call the route without login."""
        user, token = force_user_token()
        self.permission_denied("delete_user_api_token", user.id, token.id)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_not_self(self, post_event):
        """User can not delete token for other users (ui_user != user)."""
        self.login()
        token, _ = APIToken.objects.create_for_user(self.user)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user_api_token", args=(self.user.id, token.id)),
                                        follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_no_perms(self, post_event):
        """User can not delete token for service accounts without the required permissions."""
        self.login()

        token, _ = APIToken.objects.create_for_user(self.service_account)
        # service account OK, but without the required permissions
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:delete_user_api_token", args=(self.service_account.id,
                                                                token.id)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def test_delete_api_token_get(self):
        """User can see the form for deletion of own tokens."""
        self.login()
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(self.ui_user.id, token.id)), follow=True)
        self.assertTemplateUsed(response, "accounts/api_token_confirm_delete.html")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['token'], token)
        self.assertEqual(response.context['token_user'], self.ui_user)

    def test_delete_api_token_get_404(self):
        """User with required permissions will see 404 errors for no existing users/tokens."""
        self.login("accounts.view_user", "accounts.delete_apitoken")
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(0, token.id)), follow=True)
        self.assertEqual(response.status_code, 404)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(self.ui_user.id, str(uuid.uuid4()))), follow=True)
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_self(self, post_event):
        """User can delete own token."""
        self.login()
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user_api_token",
                                                args=(self.ui_user.id, token.id)), follow=True)
        self.assertTemplateUsed(response, "accounts/profile.html")
        self.assertEqual(APIToken.objects.filter(user=self.ui_user).count(), 0)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(token.id),
                 "prev_value": token.serialize_for_event()
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_api_token": [str(token.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_service_account_api_token(self, post_event):
        """User can delete service account tokens with the required permissions."""
        self.login("accounts.view_user", "accounts.delete_apitoken")
        token, _ = APIToken.objects.create_for_user(self.service_account)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:delete_user_api_token", args=(self.service_account.id, token.id)), follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertEqual(response.context["object"], self.service_account)
        self.assertEqual(APIToken.objects.filter(user=self.service_account).count(), 0)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "accounts.apitoken",
                 "pk": str(token.pk),
                 "prev_value": token.serialize_for_event()
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_api_token": [str(token.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
