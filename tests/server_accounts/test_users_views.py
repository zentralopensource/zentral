import base64
import json
import uuid
from datetime import timedelta, datetime
from django.contrib.auth.models import Group
from django.core import mail
from django.core.exceptions import ValidationError, PermissionDenied
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
import pyotp
from accounts.models import APIToken, User, UserTOTP, UserWebAuthn
from accounts.password_validation import PasswordNotAlreadyUsedValidator
from zentral.conf import ConfigDict, settings
from zentral.core.events.base import AuditEvent
from unittest.mock import patch
from tests.zentral_test_utils.login_case import LoginCase
from tests.zentral_test_utils.assertions.event_assertions import EventAssertions


class AccountUsersViewsTestCase(TestCase, LoginCase, EventAssertions):
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
        # superuser
        cls.superuser = User.objects.create_user(get_random_string(19),
                                                 "{}@zentral.io".format(get_random_string(12)),
                                                 get_random_string(12),
                                                 is_superuser=True)
        # user
        cls.user = User.objects.create_user(get_random_string(19),
                                            "{}@zentral.io".format(get_random_string(12)),
                                            get_random_string(18))
        # remote user
        cls.remote_user = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(45),
                                                   is_remote=True)
        # service account
        cls.service_account = User.objects.create_user(get_random_string(19),
                                                       "{}@zentral.io".format(get_random_string(12)),
                                                       get_random_string(12),
                                                       is_service_account=True)

    def _create_expected_updated_event_serialization(self, prev_user, changed_user):
        return {"action": "updated",
                "object": {
                    "model": "accounts.user",
                    "pk": str(prev_user.pk),
                    "new_value": self._create_user_event_serialization(changed_user),
                    "prev_value": self._create_user_event_serialization(prev_user)}}

    def _create_expected_created_event_serialization(self, user):
        return {"action": "created",
                "object": {
                    "model": "accounts.user",
                    "pk": str(user.pk),
                    "new_value": self._create_user_event_serialization(user)}}

    def _create_user_event_serialization(self, user):
        return {
            "pk": user.pk,
            "username": user.username,
            "email": user.email,
            "is_remote":  user.is_remote,
            "is_service_account":  user.is_service_account,
            "is_superuser":  user.is_superuser,
            "roles":  [{"pk": group.pk, "name": group.name} for group in user.groups.all()]
        }

    # auth utils

    def _getUser(self):
        return self.ui_user

    def _getGroup(self):
        return self.ui_group

    # simple login

    def test_simple_login_ok(self):
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "base/index.html")
        self.assertTrue(response.context["request"].user.is_authenticated)
        self.assertEqual(response.context["request"].user, self.ui_user)
        self.assertEqual(response["Cache-Control"], 'max-age=0, no-cache, no-store, must-revalidate, private')

    def test_simple_login_wrong_password(self):
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd + "0"},
                                    follow=True)
        self.assertTemplateUsed(response, "registration/login.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        self.assertContains(response, "Please enter a correct username and password.")

    def test_simple_login_already_logged_in(self):
        self.login()
        response = self.client.get(reverse("login"))
        self.assertRedirects(response, reverse("base:index"))

    def test_simple_login_already_logged_in_unsafe_redirect(self):
        self.login()
        response = self.client.get(reverse("login"), {"next": "https://www.example.com"})
        self.assertRedirects(response, reverse("base:index"))

    def test_simple_login_already_logged_ok_redirect(self):
        self.login()
        response = self.client.get(reverse("login"), {"next": reverse("accounts:profile")})
        self.assertRedirects(response, reverse("accounts:profile"))

    # login + totp

    def test_totp_user_logged_in(self):
        self.login()
        response = self.client.get(reverse("accounts:verify_totp"))
        self.assertRedirects(response, reverse("accounts:profile"))

    def test_totp_no_token(self):
        response = self.client.get(reverse("accounts:verify_totp"))
        self.assertRedirects(response, reverse("login"))

    def test_login_totp_not_ok(self):
        UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_totp.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        response = self.client.post(reverse("accounts:verify_totp"),
                                    {"verification_code": pyotp.totp.TOTP(pyotp.random_base32()).now()},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_totp.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        self.assertFormError(response.context["form"], "verification_code", "Invalid code")

    def test_login_totp_ok(self):
        user_totp = UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_totp.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        response = self.client.post(reverse("accounts:verify_totp"),
                                    {"verification_code": pyotp.totp.TOTP(user_totp.secret).now()},
                                    follow=True)
        self.assertTemplateUsed(response, "base/index.html")
        self.assertTrue(response.context["request"].user.is_authenticated)
        self.assertEqual(response.context["request"].user, self.ui_user)

    def test_login_totp_empty_error(self):
        UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_totp.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        response = self.client.post(reverse("accounts:verify_totp"),
                                    {"verification_code": " "},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_totp.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        self.assertFormError(response.context["form"], "verification_code", 'This field is required.')

    # login + webauthn

    def test_webauthn_user_logged_in(self):
        self.login()
        response = self.client.get(reverse("accounts:verify_webauthn"))
        self.assertRedirects(response, reverse("accounts:profile"))

    def test_webauthn_no_token(self):
        response = self.client.get(reverse("accounts:verify_webauthn"))
        self.assertRedirects(response, reverse("login"))

    def test_login_webauthn_not_ok(self):
        UserWebAuthn.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle="syGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k4w",
            public_key=base64.urlsafe_b64decode(
                "pQECAyYgASFYIEhW1CRfuNlIN6XTPKw0RbvzeaIlRMrDwwep-uq_-3"
                "WQIlgg1FZwd_RZRsqS_qgKCDvcVh7ScoKNo3w5h5fv3ihUSww="
            ),
            sign_count=0,
            transports=[],
        )
        response = self.client.post(reverse("login"),
                                    {"username": self.ui_user.username, "password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_webauthn.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        response = self.client.post(reverse("accounts:verify_webauthn"),
                                    {"token_response": json.dumps({})},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/verify_webauthn.html")
        self.assertFalse(response.context["request"].user.is_authenticated)
        self.assertNotContains(response, "alert-danger")

    # user list

    def test_user_list_login_redirect(self):
        self.login_redirect("users")

    def test_user_list_permission_denied(self):
        self.login()
        self.permission_denied("users")

    def test_user_list_ok(self):
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:users"))
        for text in (self.user.username, self.user.email,
                     self.remote_user.username, self.remote_user.email,
                     self.superuser.username, self.superuser.email,
                     "Users (4)"):
            self.assertContains(response, text)
        for text in (reverse("accounts:delete_user", args=(self.user.pk,)),
                     reverse("accounts:update_user", args=(self.user.pk,)),
                     reverse("accounts:delete_user", args=(self.remote_user.pk,)),
                     reverse("accounts:update_user", args=(self.remote_user.pk,)),
                     reverse("accounts:update_user", args=(self.superuser.pk,))):
            self.assertNotContains(response, text)
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.superuser.pk,)))
        self.login("accounts.view_user", "accounts.change_user", "accounts.delete_user")
        response = self.client.get(reverse("accounts:users"))
        for text in (reverse("accounts:delete_user", args=(self.user.pk,)),
                     reverse("accounts:update_user", args=(self.user.pk,)),
                     reverse("accounts:delete_user", args=(self.remote_user.pk,)),
                     reverse("accounts:update_user", args=(self.remote_user.pk,)),
                     reverse("accounts:update_user", args=(self.superuser.pk,))):
            self.assertContains(response, text)
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.superuser.pk,)))

    # profile

    def test_profile_login_redirect(self):
        self.login_redirect("profile")

    def test_profile(self):
        self.login()
        response = self.client.get(reverse("accounts:profile"))
        self.assertTemplateUsed(response, "accounts/profile.html")
        self.assertNotContains(response, self.user.username)
        self.assertContains(response, self.ui_user.username)

    def test_update_profile_login_redirect(self):
        self.login_redirect("update_profile")

    def test_update_profile_get(self):
        self.login()
        response = self.client.get(reverse("accounts:update_profile"))
        self.assertTemplateUsed(response, "accounts/profile_form.html")

    def test_update_profile_post(self):
        self.login()
        self.assertEqual(self.ui_user.items_per_page, 10)
        response = self.client.post(reverse("accounts:update_profile"), {"items_per_page": 42}, follow=True)
        self.assertTemplateUsed(response, "accounts/profile.html")
        self.ui_user.refresh_from_db()
        self.assertEqual(self.ui_user.items_per_page, 42)

    # invite

    def test_user_invite_login_redirect(self):
        self.login_redirect("invite_user")

    def test_user_invite_permission_denied(self):
        self.login("accounts.view_user")
        self.permission_denied("invite_user")

    def test_user_invite_get(self):
        self.login("accounts.add_user")
        response = self.client.get(reverse("accounts:invite_user"))
        self.assertContains(response, "Send an email invitation")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_invite_username_error(self, post_event):
        self.login("accounts.add_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:invite_user"),
                                        {"username": self.user.username,
                                         "email": "test@example.com"},
                                        follow=True)
        self.assertFormError(response.context["form"], "username", "A user with that username already exists.")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_invite_email_error(self, post_event):
        self.login("accounts.add_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:invite_user"),
                                        {"username": "test",
                                         "email": self.user.email},
                                        follow=True)
        self.assertFormError(response.context["form"], "email", "User with this Email already exists.")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_invite_email_not_allowed(self, post_event):
        self.login("accounts.add_user", "accounts.view_user")
        settings._collection["users"] = ConfigDict({"allowed_invitation_domains": ["allowed.example.com"]})
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:invite_user"),
                                        {"username": "test",
                                         "email": "test@example.com"},
                                        follow=True)
        del settings._collection["users"]
        self.assertFormError(response.context["form"], "email", "Email domain not allowed.")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_invite_any_ok(self, post_event):
        self.login("accounts.add_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:invite_user"),
                                        {"username": "test",
                                         "email": "test@example.com"},
                                        follow=True)
        self.assertEqual(len(mail.outbox), 1)
        user = User.objects.get(email="test@example.com")
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Invitation to Zentral")
        self.assertIn("Your username: test", email.body)
        for text in ("Users (5)", "test", "test@example.com"):
            self.assertContains(response, text)

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            self._create_expected_created_event_serialization(user)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(user.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_invite_allowed_ok(self, post_event):
        self.login("accounts.add_user", "accounts.view_user")
        settings._collection["users"] = ConfigDict({"allowed_invitation_domains": ["example.com", "example2.com"]})
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:invite_user"),
                                        {"username": "test",
                                         "email": "test@example.com"},
                                        follow=True)
        del settings._collection["users"]
        for text in ("Users (5)", "test", "test@example.com"):
            self.assertContains(response, text)
        user = User.objects.get(email="test@example.com")
        self.assertEqual(user.description, "")

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            self._create_expected_created_event_serialization(user)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(user.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    # create service account

    def test_create_service_account_login_redirect(self):
        self.login_redirect("create_service_account")

    def test_create_service_account_permission_denied(self):
        self.login("accounts.view_user")
        self.permission_denied("create_service_account")

    def test_create_service_account_form(self):
        self.login("accounts.add_user", "accounts.view_user", "accounts.add_apitoken")
        response = self.client.get(reverse("accounts:create_service_account"), follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertEqual(response.context['title'], 'Create service account')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_service_account(self, post_event):
        self.login("accounts.add_user", "accounts.view_user", "accounts.add_apitoken")
        username = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:create_service_account"),
                                        {"username": username,
                                         "description": "yolo fomo"},
                                        follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        service_account = response.context["object"]
        self.assertEqual(service_account.username, username)
        self.assertEqual(service_account.description, "yolo fomo")
        self.assertTrue(service_account.is_service_account)
        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            self._create_expected_created_event_serialization(service_account)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(service_account.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    def test_create_service_account_username_exists(self):
        self.login("accounts.add_user", "accounts.view_user", "accounts.add_apitoken")
        existing_username = 'yoloservice'
        User.objects.create_user(existing_username, is_service_account=True)
        response = self.client.post(reverse("accounts:create_service_account"), {"username": existing_username},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertContains(response, 'A service account with this name already exists.')

    def test_create_user_username_exists(self):
        self.login("accounts.add_user", "accounts.view_user", "accounts.add_apitoken")
        existing_username = 'yoloaccount'
        User.objects.create_user(existing_username, "{}@zentral.io".format(get_random_string(12)),
                                 get_random_string(12), is_service_account=False)
        response = self.client.post(reverse("accounts:create_service_account"), {"username": existing_username},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertContains(response, 'A user with this name already exists.')

    # update

    def test_user_update_login_redirect(self):
        self.login_redirect("update_user", self.user.id)

    def test_user_update_permission_denied(self):
        self.login("accounts.add_user")
        self.permission_denied("update_user", self.superuser.id)

    def test_user_update_404(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_user_update_get(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        self.assertContains(response, "Update user {}".format(self.user))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # not a superuser → editable

    def test_remote_user_update_get(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.remote_user.id,)))
        self.assertContains(response, "Update user {}".format(self.remote_user))
        form = response.context["form"]
        self.assertNotIn("username", form.fields)
        self.assertNotIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # not a superuser → editable

    def test_unique_superuser_update_get(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.superuser.id,)))
        self.assertContains(response, "Update user {}".format(self.superuser))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertNotIn("is_superuser", form.fields)  # unique superuser → not editable

    def test_not_unique_superuser_update_get(self):
        # add a superuser
        User.objects.create_user(get_random_string(19),
                                 "{}@zentral.io".format(get_random_string(12)),
                                 get_random_string(12),
                                 is_superuser=True)
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.superuser.id,)))
        self.assertContains(response, "Update user {}".format(self.superuser))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # not unique superuser → not editable

    def test_service_account_update_get(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.service_account.id,)))
        self.assertContains(response, "Update service account {}".format(self.service_account))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertNotIn("email", form.fields)
        self.assertIn("description", form.fields)
        self.assertNotIn("is_superuser", form.fields)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_username_error(self, post_event):
        self.login("accounts.change_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:update_user", args=(self.user.id,)),
                                        {"username": self.superuser.username,
                                         "email": self.user.email,
                                         "is_superuser": self.user.is_superuser})
        self.assertFormError(response.context["form"], "username", "A user with that username already exists.")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_email_error(self, post_event):
        self.login("accounts.change_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:update_user", args=(self.user.id,)),
                                        {"username": self.user.username,
                                         "email": self.superuser.email,
                                         "is_superuser": self.user.is_superuser})
        self.assertFormError(response.context["form"], "email", "User with this Email already exists.")
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_ok(self, post_event):
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": "toto",
                 "email": "tata@example.com",
                 "items_per_page": 10,
                 "is_superuser": self.user.is_superuser}, follow=True)

        self.assertTemplateUsed(response, "accounts/user_detail.html")
        for text in ("User tata@example.com", "toto"):
            self.assertContains(response, text)
        user = User.objects.get(email="tata@example.com")
        self.assertEqual(user.description, "")

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            self._create_expected_updated_event_serialization(self.user, user)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(self.user.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_update_ok(self, post_event):
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:update_user", args=(self.service_account.id,)),
                                        {"username": "toto",
                                         "description": "yolo2 fomo2"},
                                        follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, "Service Account toto")
        self.assertContains(response, "yolo2 fomo2")
        user = User.objects.get(username="toto")
        self.assertEqual(user.description, "yolo2 fomo2")

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            self._create_expected_updated_event_serialization(self.service_account, user)
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(self.service_account.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    # delete

    def test_user_delete_login_redirect(self):
        self.login_redirect("delete_user", self.user.id)

    def test_user_delete_permission_denied(self):
        self.login("accounts.add_user")
        self.permission_denied("delete_user", self.user.id)

    def test_user_delete_form(self):
        self.login("accounts.delete_user", "accounts.view_user")
        response = self.client.get(reverse("accounts:delete_user", args=(self.user.id,)), follow=True)
        self.assertTemplateUsed(response, "accounts/delete_user.html")
        self.assertEqual(response.context['user_to_delete'], self.user)
        self.assertEqual(response.context['title'], f"Delete {self.user.get_type_display()}")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_delete_404(self, post_event):
        self.login("accounts.delete_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user", args=(0,)))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_delete_redirect(self, post_event):
        self.login("accounts.delete_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user", args=(self.superuser.id,)))
        self.assertRedirects(response, reverse("accounts:users"))
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_delete_ok(self, post_event):
        self.login("accounts.delete_user", "accounts.view_user")
        user_str = str(self.user)
        expected_event_payload = {"action": "deleted",
                                  "object": {
                                    "model": "accounts.user",
                                    "pk": str(self.user.pk),
                                    "prev_value": {
                                        "pk": self.user.pk,
                                        "username": self.user.username,
                                        "email": self.user.email,
                                        "is_remote":  self.user.is_remote,
                                        "is_service_account":  self.user.is_service_account,
                                        "is_superuser":  self.user.is_superuser,
                                        "roles":  [{"pk": group.pk, "name": group.name}
                                                   for group in self.user.groups.all()]
                                    }}}

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user", args=(self.user.id,)), follow=True)

        self.assertContains(response, "User {} deleted".format(user_str))
        self.assertTemplateUsed(response, "accounts/user_list.html")
        self.assertContains(response, "Users (3)")

        self.assertEqual(len(callbacks), 1)

        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            expected_event_payload
        )

        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_user": [str(self.user.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])

    def test_user_delete_service_account(self):
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        self.login("accounts.delete_user", "accounts.view_user")
        response = self.client.post(reverse("accounts:delete_user", args=(service_account.id,)), follow=True)

        self.assertContains(response, "Service account {} deleted".format(service_account))
        self.assertTemplateUsed(response, "accounts/user_list.html")

    # create API token

    def test_create_api_token_login_redirect(self):
        self.login_redirect("create_user_api_token", self.user.id)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_api_token_not_self(self, post_event):
        self.login()
        # ui_user != user → 403
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(self.user.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_api_token_no_perms(self, post_event):
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        self.login()
        # service account OK, but without the required permissions
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(service_account.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def test_create_api_token_not_allowed(self):
        other_user = User.objects.create_user(get_random_string(19), "{}@zentral.io".format(get_random_string(12)),
                                              get_random_string(12), is_service_account=False)
        self.login("accounts.view_user", "accounts.add_apitoken")
        # user is not allowed to create token for other user
        response = self.client.post(
                reverse("accounts:create_user_api_token", args=(other_user.id,)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertRaises(PermissionDenied, msg="Not allowed")

    def test_create_api_token_form(self):
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        self.login("accounts.view_user", "accounts.add_apitoken")

        response = self.client.get(
                reverse("accounts:create_user_api_token", args=(service_account.id,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create API token")
        self.assertContains(response, "Give your API token a descriptive name.")
        self.assertEqual(response.context['title'], 'Create API token')
        self.assertEqual(response.context['breadcrumb_title'], 'API token')
        self.assertEqual(response.context['user'], service_account)

        expired_date = datetime.today() - timedelta(days=1)
        token_name = "totoken"
        response = self.client.post(reverse("accounts:create_user_api_token", args=(service_account.id,)),
                                    {"name": token_name, "expiry": expired_date}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "The expiration date must be in the future.")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_self_create_api_token(self, post_event):
        self.login("accounts.view_user", "accounts.add_apitoken")
        expiry_date = datetime.today() + timedelta(days=1)
        token_name = "totoken"
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:create_user_api_token", args=(self.ui_user.id,)),
                                        {"name": token_name, "expiry": expiry_date}, follow=True)
        user = response.context["object"]
        api_key = response.context["api_key"]
        api_token = user.api_token.first()

        self.assertTemplateUsed(response, "accounts/user_api_token.html")
        self.assertEqual(user, self.ui_user)
        self.assertContains(response, "Settings")
        self.assertContains(response, "Users")
        self.assertContains(response, api_key)
        self.assertEqual(APIToken.objects._hash_key(api_key), api_token.hashed_key)

        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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
    def test_server_account_create_api_token(self, post_event):
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        self.login("accounts.view_user", "accounts.add_apitoken")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_user_api_token", args=(service_account.id,)), follow=True)
        user = response.context["object"]
        api_key = response.context["api_key"]
        api_token = user.api_token.first()

        self.assertEqual(user, service_account)
        self.assertTemplateUsed(response, "accounts/user_api_token.html")
        self.assertNotContains(response, "Settings")
        self.assertContains(response, "Users")
        self.assertEqual(APIToken.objects._hash_key(api_key), service_account.api_token.first().hashed_key)

        self._assertEventsPublished(1, callbacks, post_event)
        self._assertIsAuditEvent(
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

    # delete API token

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_not_self(self, post_event):
        self.login()
        # ui_user != user → 403
        token, _ = APIToken.objects.create_for_user(self.user)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("accounts:delete_user_api_token", args=(self.user.id, token.id)),
                                        follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_no_perms(self, post_event):
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        self.login()
        token, _ = APIToken.objects.create_for_user(service_account)
        # service account OK, but without the required permissions
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:delete_user_api_token", args=(service_account.id,
                                                                token.id)), follow=True)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    def test_delete_api_token_get(self):
        self.login("accounts.view_user", "accounts.delete_apitoken")
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(self.ui_user.id, token.id)), follow=True)
        self.assertTemplateUsed(response, "accounts/api_token_confirm_delete.html")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['token'], token)
        self.assertEqual(response.context['token_user'], self.ui_user)

    def test_delete_api_token_get_404(self):
        self.login("accounts.view_user", "accounts.delete_apitoken")
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(666, token.id)), follow=True)
        self.assertEqual(response.status_code, 404)
        response = self.client.get(
            reverse("accounts:delete_user_api_token", args=(self.ui_user.id, str(uuid.uuid4()))), follow=True)
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_api_token_self(self, post_event):
        self.login()
        token, _ = APIToken.objects.create_for_user(self.ui_user)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:delete_user_api_token", args=(self.ui_user.id, token.id)), follow=True)
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
        service_account = User.objects.create_user(get_random_string(19),
                                                   "{}@zentral.io".format(get_random_string(12)),
                                                   get_random_string(12),
                                                   is_service_account=True)
        token, _ = APIToken.objects.create_for_user(service_account)
        self.login("accounts.view_user", "accounts.delete_apitoken")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:delete_user_api_token", args=(service_account.id, token.id)), follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertEqual(response.context["object"], service_account)
        self.assertEqual(APIToken.objects.filter(user=service_account).count(), 0)
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

    # verification devices list

    def test_verification_devices_login_redirect(self):
        self.login_redirect("verification_devices")

    # add TOTP device

    def test_add_totp_login_redirect(self):
        self.login_redirect("add_totp")

    def test_add_totp_get(self):
        self.login()
        response = self.client.get(reverse("accounts:add_totp"))
        self.assertTemplateUsed(response, "accounts/add_totp.html")

    def test_add_totp_validation_error(self):
        self.login()
        response = self.client.get(reverse("accounts:add_totp"))
        form = response.context["form"]
        response = self.client.post(reverse("accounts:add_totp"),
                                    {"name": get_random_string(12),
                                     "secret": form.initial_secret,
                                     "verification_code": "AAAAAA"})
        self.assertTemplateUsed(response, "accounts/add_totp.html")
        self.assertFormError(response.context["form"], "verification_code", "Wrong verification code")
        new_form = response.context["form"]
        self.assertEqual(form.initial_secret, new_form.initial_secret)

    def test_add_totp_ok(self):
        self.login()
        response = self.client.get(reverse("accounts:add_totp"))
        form = response.context["form"]
        name = get_random_string(12)
        response = self.client.post(reverse("accounts:add_totp"),
                                    {"name": name,
                                     "secret": form.initial_secret,
                                     "verification_code": pyotp.totp.TOTP(form.initial_secret).now()},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_verification_devices.html")
        self.assertContains(response, name)

    # delete TOTP device

    def test_delete_totp_login_redirect(self):
        user_totp = UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        self.login_redirect("delete_totp", user_totp.pk)

    def test_delete_totp_404(self):
        self.login()
        response = self.client.get(reverse("accounts:delete_totp", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_totp_wrong_user_404(self):
        user_totp = UserTOTP.objects.create(
            user=self.user,  # not ui_user
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        self.login()
        response = self.client.get(reverse("accounts:delete_totp", args=(user_totp.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_totp_get(self):
        user_totp = UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        self.login()
        response = self.client.get(reverse("accounts:delete_totp", args=(user_totp.pk,)))
        self.assertTemplateUsed(response, "accounts/delete_verification_device.html")
        self.assertContains(response, user_totp.name)

    def test_delete_totp_wrong_password(self):
        user_totp = UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        self.login()
        response = self.client.post(reverse("accounts:delete_totp", args=(user_totp.pk,)),
                                    {"password": self.ui_user_pwd + "1"},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/delete_verification_device.html")
        self.assertContains(response, "Your password was entered incorrectly")

    def test_delete_totp_post(self):
        user_totp = UserTOTP.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            secret=pyotp.random_base32(),
        )
        self.login()
        response = self.client.post(reverse("accounts:delete_totp", args=(user_totp.pk,)),
                                    {"password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_verification_devices.html")
        self.assertEqual(UserTOTP.objects.filter(pk=user_totp.pk).count(), 0)
        self.assertNotContains(response, user_totp.name)

    # add WebAuthn device

    def test_register_webauthn_login_redirect(self):
        self.login_redirect("register_webauthn_device")

    def test_register_webauthn_get(self):
        self.login()
        response = self.client.get(reverse("accounts:register_webauthn_device"))
        self.assertTemplateUsed(response, "accounts/register_webauthn_device.html")
        self.assertNotContains(response, "alert-danger")

    def test_register_webauthn_validation_error(self):
        self.login()
        response = self.client.get(reverse("accounts:register_webauthn_device"))
        response = self.client.post(reverse("accounts:register_webauthn_device"),
                                    {"name": get_random_string(12),
                                     "token_response": json.dumps({})})
        self.assertTemplateUsed(response, "accounts/register_webauthn_device.html")
        self.assertContains(response, "alert-danger")

    # delete WebAuthn device

    def test_delete_webauthn_device_login_redirect(self):
        user_webauthn = UserWebAuthn.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle=get_random_string(length=86, allowed_chars="s9xL"),
            public_key=b"123",
            sign_count=0,
            transports=[],
        )
        self.login_redirect("delete_webauthn_device", user_webauthn.pk)

    def test_delete_webauthn_device_404(self):
        self.login()
        response = self.client.get(reverse("accounts:delete_webauthn_device", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_webauthn_device_wrong_user_404(self):
        user_webauthn = UserWebAuthn.objects.create(
            user=self.user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle=get_random_string(length=86, allowed_chars="s9xL"),
            public_key=b"123",
            sign_count=0,
            transports=[],
        )
        self.login()
        response = self.client.get(reverse("accounts:delete_webauthn_device", args=(user_webauthn.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_webauthn_device_get(self):
        user_webauthn = UserWebAuthn.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle=get_random_string(length=86, allowed_chars="s9xL"),
            public_key=b"123",
            sign_count=0,
            transports=[],
        )
        self.login()
        response = self.client.get(reverse("accounts:delete_webauthn_device", args=(user_webauthn.pk,)))
        self.assertTemplateUsed(response, "accounts/delete_verification_device.html")
        self.assertContains(response, user_webauthn.name)

    def test_delete_webauthn_device_wrong_password(self):
        user_webauthn = UserWebAuthn.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle=get_random_string(length=86, allowed_chars="s9xL"),
            public_key=b"123",
            sign_count=0,
            transports=[],
        )
        self.login()
        response = self.client.post(reverse("accounts:delete_webauthn_device", args=(user_webauthn.pk,)),
                                    {"password": self.ui_user_pwd + "1"},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/delete_verification_device.html")
        self.assertContains(response, "Your password was entered incorrectly")

    def test_delete_webauthn_device_post(self):
        user_webauthn = UserWebAuthn.objects.create(
            user=self.ui_user,
            name=get_random_string(12),
            rp_id=settings["api"]["fqdn"],
            key_handle=get_random_string(length=86, allowed_chars="s9xL"),
            public_key=b"123",
            sign_count=0,
            transports=[],
        )
        self.login()
        response = self.client.post(reverse("accounts:delete_webauthn_device", args=(user_webauthn.pk,)),
                                    {"password": self.ui_user_pwd},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_verification_devices.html")
        self.assertEqual(UserWebAuthn.objects.filter(pk=user_webauthn.pk).count(), 0)
        self.assertNotContains(response, user_webauthn.name)

    # password reset

    def test_password_reset_get(self):
        response = self.client.get(reverse("password_reset"))
        self.assertTemplateUsed(response, "registration/password_reset_form.html")

    def test_password_reset_post(self):
        self.assertEqual(len(mail.outbox), 0)
        response = self.client.post(reverse("password_reset"), {"email": self.ui_user.email}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_reset_done.html")
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Password reset for Zentral")
        self.assertIn(f"Your username, just in case: {self.ui_user.username}", email.body)

    # password change

    def test_password_change_get(self):
        self.login()
        response = self.client.get(reverse("password_change"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")

    def test_password_change_default_password_policy_1(self):
        self.login()
        response = self.client.post(reverse("password_change"),
                                    {"old_password": self.ui_user_pwd,
                                     "new_password1": "123",
                                     "new_password2": "123"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.assertFormError(response.context["form"], "new_password2",
                             ["This password is too short. It must contain at least 8 characters.",
                              "This password is too common.",
                              "This password is entirely numeric."])

    def test_password_change_default_password_policy_2(self):
        self.login()
        response = self.client.post(reverse("password_change"),
                                    {"old_password": self.ui_user_pwd,
                                     "new_password1": self.ui_user.username,
                                     "new_password2": self.ui_user.username},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.assertFormError(response.context["form"], "new_password2",
                             ["The password is too similar to the username."])

    def test_password_change_default_password_policy_no_change(self):
        self.login()
        self.assertEqual(self.ui_user.userpasswordhistory_set.count(), 0)
        response = self.client.post(reverse("password_change"),
                                    {"old_password": self.ui_user_pwd,
                                     "new_password1": self.ui_user_pwd,
                                     "new_password2": self.ui_user_pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.assertFormError(response.context["form"], "new_password2",
                             ["Please, pick a new password."])

    def test_password_change_default_password_policy_password_already_used(self):
        new_password = get_random_string(12)
        self.ui_user.set_password(new_password)
        self.ui_user.save()
        self.login()
        self.assertEqual(self.ui_user.userpasswordhistory_set.count(), 1)
        response = self.client.post(reverse("password_change"),
                                    {"old_password": new_password,
                                     "new_password1": self.ui_user_pwd,
                                     "new_password2": self.ui_user_pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        self.assertFormError(response.context["form"], "new_password2",
                             ["You have already used that password, try another."])

    def test_password_change_post(self):
        self.login()
        response = self.client.post(reverse("password_change"),
                                    {"old_password": self.ui_user_pwd,
                                     "new_password1": "lskdjlkd1",
                                     "new_password2": "lskdjlkd1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_done.html")

    # PasswordNotAlreadyUsedValidator

    def test_password_not_already_used_help_text_default(self):
        v = PasswordNotAlreadyUsedValidator()
        self.assertEqual(v.get_help_text(), "Your password must not have been used before.")

    def test_password_not_already_used_help_text_min(self):
        v = PasswordNotAlreadyUsedValidator(min_unique_passwords=10)
        self.assertEqual(
            v.get_help_text(),
            "Your password must be different than the last 10 passwords."
        )

    def test_password_not_already_used_min_unique_passwords(self):
        for i in range(3):
            self.ui_user.set_password(get_random_string(12))
            self.ui_user.save()
            self.ui_user.refresh_from_db()
        v = PasswordNotAlreadyUsedValidator(min_unique_passwords=3)
        self.assertIsNone(v.validate(self.ui_user_pwd))
        self.assertIsNone(v.validate(self.ui_user_pwd, self.ui_user))
        v = PasswordNotAlreadyUsedValidator(min_unique_passwords=4)
        with self.assertRaises(ValidationError) as cm:
            v.validate(self.ui_user_pwd, self.ui_user)
        self.assertEqual(
            cm.exception.args,
            ('You have already used that password, try another.',
             'password_already_used',
             {'min_unique_passwords': 4})
        )
        v = PasswordNotAlreadyUsedValidator()
        with self.assertRaises(ValidationError) as cm:
            v.validate(self.ui_user_pwd, self.ui_user)
        self.assertEqual(
            cm.exception.args,
            ('You have already used that password, try another.',
             'password_already_used',
             {'min_unique_passwords': None})
        )
