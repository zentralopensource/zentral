import base64
import json
import re
import time
from unittest.mock import patch

import pyotp
from accounts.events import PasswordChangeEvent, PasswordResetRequestEvent
from accounts.forms import UpdateUserForm
from accounts.models import User, UserTOTP, UserWebAuthn
from accounts.password_validation import PasswordNotAlreadyUsedValidator
from django.contrib.auth.models import Group
from django.contrib.auth.tokens import default_token_generator
from django.core import mail
from django.core.exceptions import ValidationError
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode

from realms.models import Realm, RealmUser
from tests.zentral_test_utils.assertions.event_assertions import EventAssertions
from tests.zentral_test_utils.login_case import LoginCase
from zentral.conf import ConfigDict, settings
from zentral.core.events.base import AuditEvent


def verification_code(secret):
    totp = pyotp.totp.TOTP(secret)
    # the views verify without a valid window, so a code generated at the end of its
    # time step is refused if the step rolls over before the response is rendered
    if totp.interval - time.time() % totp.interval < 2:
        time.sleep(2)
    return totp.now()


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
        # realm + matching realm user for ui_user (used by tests that need a remote session)
        cls.realm = Realm.objects.create(
            name=get_random_string(12),
            enabled_for_login=True,
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        cls.realm_user = RealmUser.objects.create(
            realm=cls.realm,
            claims={"username": cls.ui_user.username, "email": cls.ui_user.email},
            username=cls.ui_user.username,
            email=cls.ui_user.email,
        )

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

    def _get_user(self):
        return self.ui_user

    def _get_group(self):
        return self.ui_group

    def _get_url_namespace(self):
        return "accounts"

    def _get_realm(self):
        return self.realm

    def _get_realm_user(self):
        return self.realm_user

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
                                    {"verification_code": verification_code(user_totp.secret)},
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

    def test_user_list_realm_session_of_an_inactive_user(self):
        self.login("accounts.view_user", realm_user=True)
        response = self.client.get(reverse("accounts:users"))
        self.assertEqual(response.status_code, 200)
        self.ui_user.is_active = False
        self.ui_user.save()
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
                     reverse("accounts:update_user", args=(self.remote_user.pk,))):
            self.assertContains(response, text)
        # only a superuser can change a superuser
        self.assertNotContains(response, reverse("accounts:update_user", args=(self.superuser.pk,)))
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.superuser.pk,)))
        self._promote_ui_user_to_superuser()
        response = self.client.get(reverse("accounts:users"))
        self.assertContains(response, reverse("accounts:update_user", args=(self.superuser.pk,)))
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.superuser.pk,)))

    def test_user_list_superuser_column(self):
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:users"))
        self.assertNotContains(response, "Superuser?")
        # the remote user
        self.assertContains(response, "<td>yes</td>", count=1)
        self._promote_ui_user_to_superuser()
        response = self.client.get(reverse("accounts:users"))
        self.assertContains(response, "Superuser?", count=1)
        # the remote user, the superuser and the promoted UI user
        self.assertContains(response, "<td>yes</td>", count=3)

    def _force_realm_user(self, realm=None, username=None, email=None, scim_active=None):
        # scim_active None: a realm user that a login made
        return RealmUser.objects.create(
            realm=realm or self.realm,
            scim_active=bool(scim_active),
            scim_updated_at=None if scim_active is None else timezone.now(),
            username=username or get_random_string(12),
            email=email or "{}@zentral.io".format(get_random_string(12)),
        )

    def test_user_list_realm_users(self):
        # the email matches, SCIM inactive
        superuser_realm_user = self._force_realm_user(email=self.superuser.email, scim_active=False)
        # the username matches, SCIM active
        remote_user_realm_user = self._force_realm_user(username=self.remote_user.username, scim_active=True)
        # the email of one user and the username of another, in another realm: on both rows
        other_realm = Realm.objects.create(
            name=get_random_string(12),
            enabled_for_login=True,
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        conflict_realm_user = self._force_realm_user(realm=other_realm, email=self.user.email,
                                                     username=self.remote_user.username)
        # realm not enabled for login
        no_login_realm = Realm.objects.create(
            name=get_random_string(12),
            enabled_for_login=False,
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        self._force_realm_user(realm=no_login_realm, email=self.user.email, scim_active=False)
        # self.ui_user matches self.realm_user, made by a login
        self.login("accounts.view_user", "realms.view_realmuser")
        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse("accounts:users"))
        realm_user_queries = [q["sql"] for q in queries.captured_queries if '"realms_realmuser"' in q["sql"]]
        self.assertEqual(len(realm_user_queries), 1)
        self.assertNotIn('"accounts_user"', realm_user_queries[0])
        self.assertEqual(
            {u.pk: {ru.pk for ru in u.realm_users} for u in response.context["users"]},
            {self.ui_user.pk: {self.realm_user.pk},
             self.superuser.pk: {superuser_realm_user.pk},
             self.user.pk: {conflict_realm_user.pk},
             self.remote_user.pk: {remote_user_realm_user.pk, conflict_realm_user.pk}}
        )
        self.assertContains(response, "Realm users", count=1)
        # only the realm user that SCIM deactivated
        self.assertContains(response, "SCIM inactive", count=1)
        self.assertNotContains(response, "SCIM active")
        self.assertContains(response, superuser_realm_user.get_absolute_url(), count=1)
        self.assertContains(response, conflict_realm_user.get_absolute_url(), count=2)

    def test_user_list_realm_users_without_the_realm_user_permission(self):
        self._force_realm_user(email=self.superuser.email, scim_active=False)
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:users"))
        self.assertFalse(any(hasattr(u, "realm_users") for u in response.context["users"]))
        self.assertNotContains(response, "Realm users")
        self.assertNotContains(response, "SCIM inactive")

    def test_user_list_remote_session_no_write_links(self):
        self.login("accounts.view_user", "accounts.add_user", "accounts.add_apitoken",
                   "accounts.change_user", "accounts.delete_user", realm_user=True)
        response = self.client.get(reverse("accounts:users"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["request"].realm_authentication_session.is_remote)
        self.assertContains(response, self.user.username)
        for text in (reverse("accounts:invite_user"),
                     reverse("accounts:create_service_account"),
                     reverse("accounts:delete_user", args=(self.user.pk,)),
                     reverse("accounts:update_user", args=(self.user.pk,)),
                     reverse("accounts:delete_user", args=(self.service_account.pk,)),
                     reverse("accounts:update_user", args=(self.service_account.pk,))):
            self.assertNotContains(response, text)

    def test_superuser_detail_no_update_link_for_non_superuser(self):
        self.login("accounts.view_user", "accounts.change_user")
        response = self.client.get(reverse("accounts:user", args=(self.superuser.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("accounts:update_user", args=(self.superuser.pk,)))

    def test_superuser_detail_update_link_for_superuser(self):
        self._promote_ui_user_to_superuser()
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:user", args=(self.superuser.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("accounts:update_user", args=(self.superuser.pk,)))

    def test_user_detail_remote_session_no_write_links(self):
        self.login("accounts.view_user", "accounts.change_user", "accounts.delete_user", realm_user=True)
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["request"].realm_authentication_session.is_remote)
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.user.pk,)))
        self.assertNotContains(response, reverse("accounts:update_user", args=(self.user.pk,)))

    # user detail — policies that reference the user

    def test_view_user_realm_users(self):
        scim_realm_user = self._force_realm_user(email=self.user.email, scim_active=False)
        no_login_realm = Realm.objects.create(
            name=get_random_string(12),
            enabled_for_login=False,
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        self._force_realm_user(realm=no_login_realm, email=self.user.email, scim_active=False)
        self.login("accounts.view_user", "realms.view_realmuser")
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        self.assertEqual(response.context["realm_users"], [scim_realm_user])
        self.assertContains(response, "Realm user (1)")
        self.assertContains(response, "SCIM active?")
        self.assertContains(response, "Last SCIM update")
        self.assertContains(response, scim_realm_user.get_absolute_url())
        self.assertContains(response, "<td>no</td>")
        self.assertContains(response, "0\xa0minutes ago")
        self.assertNotContains(response, "<td>-</td>")
        # a realm user that a login made
        response = self.client.get(reverse("accounts:user", args=(self.ui_user.pk,)))
        self.assertEqual(response.context["realm_users"], [self.realm_user])
        self.assertContains(response, self.realm_user.get_absolute_url())
        self.assertContains(response, "<td>-</td>", count=2)
        self.assertNotContains(response, "ago</span>")
        # no realm user
        response = self.client.get(reverse("accounts:user", args=(self.superuser.pk,)))
        self.assertEqual(response.context["realm_users"], [])
        self.assertContains(response, "Realm users (0)")
        self.assertNotContains(response, "SCIM active?")

    def test_view_user_realm_users_service_account(self):
        self.login("accounts.view_user", "realms.view_realmuser")
        response = self.client.get(reverse("accounts:user", args=(self.service_account.pk,)))
        self.assertNotIn("realm_users", response.context)
        self.assertNotContains(response, "Realm user")

    def test_view_user_realm_users_without_the_realm_user_permission(self):
        scim_realm_user = self._force_realm_user(email=self.user.email, scim_active=False)
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        self.assertNotIn("realm_users", response.context)
        self.assertNotContains(response, "Realm user")
        self.assertNotContains(response, scim_realm_user.get_absolute_url())

    def test_view_user_lists_policies_referencing_user(self):
        from accounts.models import Policy
        p = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == User::"{self.user.pk}", action, resource);\n',
        )
        # A policy referencing a different user — must NOT appear.
        other_user = User.objects.create_user(
            get_random_string(12), f"{get_random_string(12)}@zentral.io", get_random_string(12),
        )
        other_policy = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == User::"{other_user.pk}", action, resource);\n',
        )
        self.login("accounts.view_user", "accounts.view_policy")
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, p.name)
        self.assertContains(response, reverse("accounts:policy", args=(p.pk,)))
        self.assertNotContains(response, other_policy.name)

    def test_view_service_account_lists_policies_referencing_it(self):
        from accounts.models import Policy
        p = Policy.objects.create(
            name=get_random_string(12),
            source=(
                f'permit (principal == ServiceAccount::"{self.service_account.pk}", '
                'action, resource);\n'
            ),
        )
        self.login("accounts.view_user", "accounts.view_policy")
        response = self.client.get(reverse("accounts:user", args=(self.service_account.pk,)))
        self.assertContains(response, p.name)
        self.assertContains(response, reverse("accounts:policy", args=(p.pk,)))

    # user detail — PBAC principal representation

    def test_view_user_shows_pbac_principal(self):
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.assertContains(response, f'<code>User::&quot;{self.user.pk}&quot;</code>', html=False)

    def test_view_service_account_shows_pbac_principal(self):
        self.login("accounts.view_user")
        response = self.client.get(reverse("accounts:user", args=(self.service_account.pk,)))
        self.assertContains(
            response, f'<code>ServiceAccount::&quot;{self.service_account.pk}&quot;</code>', html=False
        )

    def test_view_user_policies_section_hidden_without_view_policy_perm(self):
        from accounts.models import Policy
        Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == User::"{self.user.pk}", action, resource);\n',
        )
        self.login("accounts.view_user")  # no accounts.view_policy
        response = self.client.get(reverse("accounts:user", args=(self.user.pk,)))
        # The row's <th>Polic…</th> shouldn't be in the rendered HTML.
        self.assertNotContains(response, "<th>Polic")

    # profile

    def test_profile_login_redirect(self):
        self.login_redirect("profile")

    def test_profile(self):
        self.login()
        response = self.client.get(reverse("accounts:profile"))
        self.assertTemplateUsed(response, "accounts/profile.html")
        self.assertNotContains(response, self.user.username)
        self.assertContains(response, self.ui_user.username)
        self.assertContains(response, ">Change password</a>")
        self.assertContains(response, ">Manage your verification devices</a>")
        self.assertContains(response, "Global items per page")

    def test_profile_remote_user(self):
        self.client.force_login(self.remote_user)
        response = self.client.get(reverse("accounts:profile"))
        self.assertTemplateUsed(response, "accounts/profile.html")
        self.assertContains(response, self.remote_user.username)
        self.assertNotContains(response, ">Change password</a>")
        self.assertNotContains(response, ">Manage your verification devices</a>")
        self.assertContains(response, "Global items per page")

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

    def test_user_invite_remote_session_permission_denied(self):
        self.login("accounts.add_user", realm_user=True)
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

    def test_create_service_account_remote_session_permission_denied(self):
        self.login("accounts.add_user", "accounts.add_apitoken", realm_user=True)
        self.permission_denied("create_service_account")

    def test_create_service_account_form(self):
        self.login("accounts.add_user", "accounts.view_user")
        response = self.client.get(reverse("accounts:create_service_account"), follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertEqual(response.context['title'], 'Create service account')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_service_account(self, post_event):
        self.login("accounts.add_user", "accounts.view_user")
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
        self.login("accounts.add_user", "accounts.view_user")
        existing_username = 'yoloservice'
        User.objects.create_user(existing_username, is_service_account=True)
        response = self.client.post(reverse("accounts:create_service_account"), {"username": existing_username},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertContains(response, 'A service account with this name already exists.')

    def test_create_user_username_exists(self):
        self.login("accounts.add_user", "accounts.view_user")
        existing_username = 'yoloaccount'
        User.objects.create_user(existing_username, "{}@zentral.io".format(get_random_string(12)),
                                 get_random_string(12), is_service_account=False)
        response = self.client.post(reverse("accounts:create_service_account"), {"username": existing_username},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_form.html")
        self.assertContains(response, 'A user with this name already exists.')

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_non_superuser_service_account_flow_with_own_role(self, post_event):
        # a role administrator who is not a superuser: create a service account in a role they have,
        # give it a token, change it
        other_group = Group.objects.create(name=get_random_string(12))
        self.login("accounts.add_user", "accounts.change_user", "accounts.view_user",
                   "accounts.add_apitoken", "accounts.view_apitoken")
        self.assertFalse(self.ui_user.is_superuser)
        response = self.client.get(reverse("accounts:create_service_account"))
        self.assertEqual(response.status_code, 200)
        widget = response.context["form"].fields["groups"].widget
        self.assertEqual(widget.disabled_values, {other_group.pk})
        username = "ci-bot-" + get_random_string(6)
        response = self.client.post(reverse("accounts:create_service_account"),
                                    {"username": username,
                                     "description": "",
                                     "groups": [self.ui_group.pk]},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        service_account = User.objects.get(username=username)
        self.assertTrue(service_account.is_service_account)
        self.assertFalse(service_account.is_superuser)
        self.assertEqual(list(service_account.groups.all()), [self.ui_group])
        self.assertTrue(response.context["can_add_token"])
        self.assertContains(response, reverse("accounts:create_user_api_token", args=(service_account.pk,)))
        self.assertContains(response, reverse("accounts:update_user", args=(service_account.pk,)))
        # token
        response = self.client.post(reverse("accounts:create_user_api_token", args=(service_account.pk,)),
                                    {"name": "ci"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/user_api_token.html")
        self.assertEqual(service_account.apitoken_set.count(), 1)
        # change
        response = self.client.post(reverse("accounts:update_user", args=(service_account.pk,)),
                                    {"username": username,
                                     "description": "CI",
                                     "groups": [self.ui_group.pk]},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        service_account.refresh_from_db()
        self.assertEqual(service_account.description, "CI")
        self.assertEqual(list(service_account.groups.all()), [self.ui_group])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_non_superuser_user_flow_with_own_role(self, post_event):
        self.login("accounts.add_user", "accounts.change_user", "accounts.view_user")
        self.assertFalse(self.ui_user.is_superuser)
        self.client.post(reverse("accounts:invite_user"),
                         {"username": "test",
                          "email": "test@example.com"},
                         follow=True)
        user = User.objects.get(email="test@example.com")
        self.assertFalse(user.is_superuser)
        self.assertEqual(len(mail.outbox), 1)
        response = self.client.post(reverse("accounts:update_user", args=(user.pk,)),
                                    {"username": "test",
                                     "email": "test@example.com",
                                     "items_per_page": 10,
                                     "groups": [self.ui_group.pk]},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        user.refresh_from_db()
        self.assertEqual(list(user.groups.all()), [self.ui_group])
        self.assertFalse(user.is_superuser)

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

    def _promote_ui_user_to_superuser(self):
        self.ui_user.is_superuser = True
        self.ui_user.save()

    def test_user_update_get(self):
        self._promote_ui_user_to_superuser()
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        self.assertContains(response, "Update user {}".format(self.user))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # local superuser requester → can grant

    def test_remote_user_update_get(self):
        self._promote_ui_user_to_superuser()
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.remote_user.id,)))
        self.assertContains(response, "Update user {}".format(self.remote_user))
        form = response.context["form"]
        self.assertNotIn("username", form.fields)
        self.assertNotIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # local superuser requester → can grant

    def test_unique_superuser_update_get(self):
        # ui_user is the only superuser and edits itself: it must not be able
        # to remove its own superuser flag, otherwise the system would be left
        # with no superuser at all.
        self.superuser.is_superuser = False
        self.superuser.save()
        self._promote_ui_user_to_superuser()
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.ui_user.id,)))
        self.assertContains(response, "Update user {}".format(self.ui_user))
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
        self._promote_ui_user_to_superuser()
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.superuser.id,)))
        self.assertContains(response, "Update user {}".format(self.superuser))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)
        self.assertNotIn("description", form.fields)
        self.assertIn("is_superuser", form.fields)  # not unique superuser → editable

    def test_non_superuser_requester_cannot_see_username_and_email(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        form = response.context["form"]
        self.assertNotIn("username", form.fields)
        self.assertNotIn("email", form.fields)
        self.assertIn("groups", form.fields)

    def test_user_update_own_username_and_email_get(self):
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.ui_user.id,)))
        form = response.context["form"]
        self.assertIn("username", form.fields)
        self.assertIn("email", form.fields)

    def test_user_update_own_remote_session_permission_denied(self):
        self.login("accounts.change_user", realm_user=True)
        self.permission_denied("update_user", self.ui_user.id)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_non_superuser_requester_cannot_change_username_and_email(self, post_event):
        # smuggling a username and an email through a POST must be ignored
        self.login("accounts.change_user", "accounts.view_user")
        username = self.user.username
        email = self.user.email
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": "toto",
                 "email": "tata@example.com",
                 "items_per_page": 10},
                follow=True,
            )
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.user.refresh_from_db()
        self.assertEqual(self.user.username, username)
        self.assertEqual(self.user.email, email)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_own_username_and_email(self, post_event):
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("accounts:update_user", args=(self.ui_user.id,)),
                {"username": "toto",
                 "email": "tata@example.com",
                 "groups": [self.ui_group.pk],
                 "items_per_page": 10},
                follow=True,
            )
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        self.ui_user.refresh_from_db()
        self.assertEqual(self.ui_user.username, "toto")
        self.assertEqual(self.ui_user.email, "tata@example.com")

    def test_superuser_update_non_superuser_requester_403(self):
        # a write action includes the read of its resource: the refusal hides nothing, and is logged
        self.login("accounts.change_user")
        with self.assertLogs("zentral.accounts.views.users", level="ERROR") as cm:
            response = self.client.get(reverse("accounts:update_user", args=(self.superuser.id,)))
        self.assertEqual(response.status_code, 403)
        self.assertEqual(cm.output, [f"ERROR:zentral.accounts.views.users:Permission denied on superuser "
                                     f"{self.superuser.pk}"])
        with self.assertNoLogs("zentral.accounts.views.users", level="ERROR"):
            response = self.client.get(reverse("accounts:update_user", args=(0,)))
        self.assertEqual(response.status_code, 404)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_update_post_non_superuser_requester_403(self, post_event):
        self.login("accounts.change_user", "accounts.view_user")
        email = "{}@zentral.io".format(get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks, \
             self.assertLogs("zentral.accounts.views.users", level="ERROR"):
            response = self.client.post(
                reverse("accounts:update_user", args=(self.superuser.id,)),
                {"username": self.superuser.username,
                 "email": email,
                 "items_per_page": 10},
            )
        self.assertEqual(response.status_code, 403)
        self.superuser.refresh_from_db()
        self.assertNotEqual(self.superuser.email, email)
        self.assertTrue(self.superuser.is_superuser)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    def test_non_superuser_requester_cannot_see_is_superuser(self):
        # ui_user has change_user perm but is not a superuser
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        form = response.context["form"]
        self.assertNotIn("is_superuser", form.fields)

    def test_user_update_remote_session_superuser_permission_denied(self):
        self._promote_ui_user_to_superuser()
        self.login(realm_user=True)
        self.permission_denied("update_user", self.user.id)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_non_superuser_requester_cannot_grant_superuser(self, post_event):
        # smuggling is_superuser=True through a POST must be ignored
        self.login("accounts.change_user", "accounts.view_user")
        self.assertFalse(self.user.is_superuser)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "is_superuser": "on"},
                follow=True,
            )
        self.user.refresh_from_db()
        self.assertFalse(self.user.is_superuser)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertFalse(event.payload["object"]["new_value"]["is_superuser"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_remote_session_post_permission_denied(self, post_event):
        self.login("accounts.change_user", "accounts.view_user", realm_user=True)
        # the realm login posts a login event
        post_event.reset_mock()
        email = "{}@zentral.io".format(get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": email,
                 "items_per_page": 10},
            )
        self.assertEqual(response.status_code, 403)
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.email, email)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_local_superuser_requester_can_grant_superuser(self, post_event):
        self._promote_ui_user_to_superuser()
        self.login("accounts.change_user", "accounts.view_user")
        self.assertFalse(self.user.is_superuser)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "is_superuser": "on"},
                follow=True,
            )
        self.user.refresh_from_db()
        self.assertTrue(self.user.is_superuser)
        self.assertEqual(len(callbacks), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertTrue(event.payload["object"]["new_value"]["is_superuser"])

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
        self._promote_ui_user_to_superuser()
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
        self._promote_ui_user_to_superuser()
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
        self._promote_ui_user_to_superuser()
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

    # role-membership grant restrictions

    def test_user_update_groups_field_labeled_as_roles(self):
        # Zentral UI uses "Roles", not Django's auto-generated "Groups".
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        field = response.context["form"].fields["groups"]
        self.assertEqual(field.label, "Roles")
        self.assertEqual(field.help_text, "The roles this user belongs to.")
        self.assertEqual(field.widget.attrs.get("size"), 10)

    def test_service_account_create_groups_field_labeled_as_roles(self):
        self.login("accounts.add_user")
        response = self.client.get(reverse("accounts:create_service_account"))
        field = response.context["form"].fields["groups"]
        self.assertEqual(field.label, "Roles")
        self.assertEqual(field.help_text, "The roles this user belongs to.")
        self.assertEqual(field.widget.attrs.get("size"), 10)

    def test_mixin_methods_noop_when_groups_field_is_absent(self):
        # Defensive guards: if a form using the mixin doesn't expose a "groups"
        # field, _prepare_groups_field and _disable_ungrantable_group_options
        # must early-return cleanly instead of raising KeyError. Triggered by
        # calling them with a field_name that isn't present on the form.
        from accounts.forms import ServiceAccountForm
        form = ServiceAccountForm(request_user=self.ui_user)
        form._prepare_groups_field(field_name="not_a_field")
        form._disable_ungrantable_group_options(field_name="not_a_field")
        # If we got here without raising, the guards did their job.
        self.assertNotIn("not_a_field", form.fields)

    def test_role_grant_forms_need_the_request_user(self):
        from accounts.forms import ServiceAccountForm
        for form_class in (ServiceAccountForm, UpdateUserForm):
            with self.assertRaises(KeyError):
                form_class(instance=self.user)

    def _role_option_tag(self, html, pk):
        """Return the rendered ``<option>`` tag for a role/group pk in the
        roles ``<select>``, or None if it isn't rendered at all. Asserting on
        the real HTML — not just ``widget.disabled_values`` — is what catches
        the choices-not-wired-up regression: the widget can carry the correct
        disabled_values yet render zero options (so nothing is disabled because
        nothing is rendered).
        """
        match = re.search(r'<option value="{}"[^>]*>'.format(pk), html)
        return match.group(0) if match else None

    def test_user_update_widget_disables_ungrantable_groups(self):
        # The widget mirrors the validation rule so operators see upfront
        # which groups they can't grant. Groups the target already belongs to
        # stay selectable (so the actor can remove or keep them).
        ungrantable = Group.objects.create(name=get_random_string(12))
        already_assigned = Group.objects.create(name=get_random_string(12))
        self.user.groups.add(already_assigned)
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        widget = response.context["form"].fields["groups"].widget
        self.assertIn(ungrantable.pk, widget.disabled_values)
        self.assertNotIn(self.ui_group.pk, widget.disabled_values)  # actor's own group
        self.assertNotIn(already_assigned.pk, widget.disabled_values)  # already on target
        # the disabled_values attribute must actually reach the rendered HTML
        html = response.content.decode()
        ungrantable_option = self._role_option_tag(html, ungrantable.pk)
        self.assertIsNotNone(ungrantable_option)
        self.assertIn("disabled", ungrantable_option)
        own_option = self._role_option_tag(html, self.ui_group.pk)
        self.assertIsNotNone(own_option)
        self.assertNotIn("disabled", own_option)
        assigned_option = self._role_option_tag(html, already_assigned.pk)
        self.assertIsNotNone(assigned_option)
        self.assertNotIn("disabled", assigned_option)

    def test_user_update_widget_not_filtered_for_superuser(self):
        # Superusers see the unmodified default widget — no disabled options.
        self.ui_user.is_superuser = True
        self.ui_user.save()
        group = Group.objects.create(name=get_random_string(12))
        self.login("accounts.change_user")
        response = self.client.get(reverse("accounts:update_user", args=(self.user.id,)))
        widget = response.context["form"].fields["groups"].widget
        self.assertFalse(hasattr(widget, "disabled_values"))
        # the option still renders, just without the disabled attribute
        html = response.content.decode()
        option = self._role_option_tag(html, group.pk)
        self.assertIsNotNone(option)
        self.assertNotIn("disabled", option)

    def test_service_account_create_widget_disables_ungrantable_groups(self):
        # Same rule applies on the creation path — without it, "create a SA
        # in role X" is the escalation vector.
        ungrantable = Group.objects.create(name=get_random_string(12))
        self.login("accounts.add_user")
        response = self.client.get(reverse("accounts:create_service_account"))
        widget = response.context["form"].fields["groups"].widget
        self.assertIn(ungrantable.pk, widget.disabled_values)
        self.assertNotIn(self.ui_group.pk, widget.disabled_values)
        # the disabled_values attribute must actually reach the rendered HTML
        html = response.content.decode()
        ungrantable_option = self._role_option_tag(html, ungrantable.pk)
        self.assertIsNotNone(ungrantable_option)
        self.assertIn("disabled", ungrantable_option)
        own_option = self._role_option_tag(html, self.ui_group.pk)
        self.assertIsNotNone(own_option)
        self.assertNotIn("disabled", own_option)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_cannot_add_group_actor_is_not_member_of(self, post_event):
        # Non-superuser must not grant memberships they don't have themselves.
        other_group = Group.objects.create(name=get_random_string(12))
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "groups": [other_group.pk]},
            )
        self.assertFormError(
            response.context["form"], "groups",
            f"You cannot grant role membership you don't have: {other_group.name}.",
        )
        self.user.refresh_from_db()
        self.assertNotIn(other_group, self.user.groups.all())
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_can_add_group_actor_is_member_of(self, post_event):
        # Granting a group the actor already belongs to is fine.
        self.login("accounts.change_user", "accounts.view_user")
        self.assertNotIn(self.ui_group, self.user.groups.all())
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "groups": [self.ui_group.pk]},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertIn(self.ui_group, self.user.groups.all())
        self.assertEqual(len(callbacks), 1)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_user_update_can_remove_group_actor_is_not_member_of(self, post_event):
        # Removal is intentionally not restricted by the rule — escalation risk
        # is granting, not revoking. The actor here is not in other_group, but
        # the target user is, and the actor is allowed to take them out.
        other_group = Group.objects.create(name=get_random_string(12))
        self.user.groups.add(other_group)
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "groups": []},
                follow=True,
            )
        self.user.refresh_from_db()
        self.assertNotIn(other_group, self.user.groups.all())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_update_can_add_any_group(self, post_event):
        # Superusers are exempt from the grant-without-hold check.
        self.ui_user.is_superuser = True
        self.ui_user.save()
        other_group = Group.objects.create(name=get_random_string(12))
        self.assertNotIn(other_group, self.ui_user.groups.all())
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(
                reverse("accounts:update_user", args=(self.user.id,)),
                {"username": self.user.username,
                 "email": self.user.email,
                 "items_per_page": 10,
                 "groups": [other_group.pk]},
                follow=True,
            )
        self.user.refresh_from_db()
        self.assertIn(other_group, self.user.groups.all())

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_update_cannot_add_group_actor_is_not_member_of(self, post_event):
        # Same rule for the service-account form.
        other_group = Group.objects.create(name=get_random_string(12))
        self.login("accounts.change_user", "accounts.view_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:update_user", args=(self.service_account.id,)),
                {"username": self.service_account.username,
                 "description": "",
                 "groups": [other_group.pk]},
            )
        self.assertFormError(
            response.context["form"], "groups",
            f"You cannot grant role membership you don't have: {other_group.name}.",
        )
        self.service_account.refresh_from_db()
        self.assertNotIn(other_group, self.service_account.groups.all())
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_service_account_create_cannot_assign_group_actor_is_not_member_of(self, post_event):
        # Creation path — the rule must apply at creation time too, otherwise
        # "create a service account in role X" becomes the escalation vector.
        other_group = Group.objects.create(name=get_random_string(12))
        self.login("accounts.add_user")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("accounts:create_service_account"),
                {"username": "ci-bot-" + get_random_string(6),
                 "description": "",
                 "groups": [other_group.pk]},
            )
        self.assertFormError(
            response.context["form"], "groups",
            f"You cannot grant role membership you don't have: {other_group.name}.",
        )
        self.assertEqual(len(callbacks), 0)
        self.assertEqual(len(post_event.call_args_list), 0)

    # delete

    def test_user_delete_login_redirect(self):
        self.login_redirect("delete_user", self.user.id)

    def test_user_delete_login_redirect_same_answer_for_each_id(self):
        # without a login, an unknown id and a superuser get the answer of a user
        for pk in (self.user.id, self.superuser.id, 0):
            self.login_redirect("delete_user", pk)
            self.login_redirect("delete_user", pk, data={"yolo": "fomo"})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_superuser_delete_non_superuser_requester_403(self, post_event):
        self.login("accounts.delete_user", "accounts.view_user")
        for method in ("get", "post"):
            with self.assertLogs("zentral.accounts.views.users", level="ERROR") as cm, \
                 self.captureOnCommitCallbacks(execute=True) as callbacks:
                response = getattr(self.client, method)(reverse("accounts:delete_user", args=(self.superuser.id,)))
            self.assertEqual(response.status_code, 403)
            self.assertEqual(cm.output, [f"ERROR:zentral.accounts.views.users:Permission denied on superuser "
                                         f"{self.superuser.pk}"])
            self.assertEqual(len(callbacks), 0)
        self.assertTrue(User.objects.filter(pk=self.superuser.pk).exists())
        post_event.assert_not_called()

    def test_user_delete_permission_denied(self):
        self.login("accounts.add_user")
        self.permission_denied("delete_user", self.user.id)

    def test_user_delete_remote_session_permission_denied(self):
        self.login("accounts.delete_user", "accounts.view_user", realm_user=True)
        response = self.client.post(reverse("accounts:delete_user", args=(self.user.id,)))
        self.assertEqual(response.status_code, 403)
        self.assertTrue(User.objects.filter(pk=self.user.pk).exists())

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
        # nobody deletes a superuser, a superuser included
        self._promote_ui_user_to_superuser()
        self.login("accounts.delete_user", "accounts.view_user")
        for method in ("get", "post"):
            with self.captureOnCommitCallbacks(execute=True) as callbacks:
                response = getattr(self.client, method)(reverse("accounts:delete_user", args=(self.superuser.id,)))
            self.assertRedirects(response, reverse("accounts:users"))
            self.assertEqual(len(callbacks), 0)
        self.assertTrue(User.objects.filter(pk=self.superuser.pk).exists())
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
                                     "verification_code": verification_code(form.initial_secret)},
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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_password_reset_post(self, post_event):
        self.assertEqual(len(mail.outbox), 0)
        response = self.client.post(reverse("password_reset"), {"email": self.ui_user.email}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_reset_done.html")
        self.assertEqual(len(mail.outbox), 1)
        email = mail.outbox[0]
        self.assertEqual(email.subject, "Password reset for Zentral")
        self.assertIn(f"Your username, just in case: {self.ui_user.username}", email.body)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, PasswordResetRequestEvent)
        self.assertEqual(
            event.payload,
            {"email": self.ui_user.email,
             "users": [{"pk": self.ui_user.pk, "username": self.ui_user.username}]}
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_password_reset_post_unknown_email(self, post_event):
        email = "{}@zentral.io".format(get_random_string(12))
        response = self.client.post(reverse("password_reset"), {"email": email}, follow=True)
        self.assertTemplateUsed(response, "registration/password_reset_done.html")
        self.assertEqual(len(mail.outbox), 0)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, PasswordResetRequestEvent)
        self.assertEqual(event.payload, {"email": email, "users": []})

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_password_reset_confirm_post(self, post_event):
        uid = urlsafe_base64_encode(force_bytes(self.ui_user.pk))
        token = default_token_generator.make_token(self.ui_user)
        response = self.client.get(reverse("password_reset_confirm", args=(uid, token)), follow=True)
        self.assertTemplateUsed(response, "registration/password_reset_confirm.html")
        response = self.client.post(response.redirect_chain[-1][0],
                                    {"new_password1": "lskdjlkd1",
                                     "new_password2": "lskdjlkd1"},
                                    follow=True)
        self.assertTemplateUsed(response, "registration/password_reset_complete.html")
        self.ui_user.refresh_from_db()
        self.assertTrue(self.ui_user.check_password("lskdjlkd1"))
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, PasswordChangeEvent)
        self.assertEqual(
            event.payload,
            {"password_reset": True,
             "user": {"pk": self.ui_user.pk, "username": self.ui_user.username}}
        )

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

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_password_change_post(self, post_event):
        self.login()
        response = self.client.post(reverse("password_change"),
                                    {"old_password": self.ui_user_pwd,
                                     "new_password1": "lskdjlkd1",
                                     "new_password2": "lskdjlkd1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "registration/password_change_done.html")
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, PasswordChangeEvent)
        self.assertEqual(event.payload, {"password_reset": False})
        self.assertEqual(event.metadata.request.user.id, self.ui_user.pk)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_password_change_post_error_no_event(self, post_event):
        self.login()
        response = self.client.post(reverse("password_change"),
                                    {"old_password": get_random_string(12),
                                     "new_password1": "lskdjlkd1",
                                     "new_password2": "lskdjlkd1"},
                                    follow=True)
        self.assertTemplateUsed(response, "registration/password_change_form.html")
        post_event.assert_not_called()

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
