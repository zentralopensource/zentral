import uuid
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AccountUsersViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # superuser
        cls.su_pwd = get_random_string(17)
        cls.superuser = User.objects.create_user(get_random_string(21),
                                                 "{}@zentral.io".format(str(uuid.uuid4())),
                                                 cls.su_pwd,
                                                 is_superuser=True)
        # user
        cls.pwd = get_random_string(18)
        cls.user = User.objects.create_user(get_random_string(19),
                                            "{}@zentral.io".format(str(uuid.uuid4())),
                                            cls.pwd)
        # remote user
        cls.remoteuser = User.objects.create_user(get_random_string(19),
                                                  "{}@zentral.io".format(str(uuid.uuid4())),
                                                  get_random_string(45),
                                                  is_remote=True)

    # auth utils

    def login_redirect(self, url_name, *args):
        url = reverse("accounts:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def permission_denied(self, url_name, *args):
        url = reverse("accounts:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 403)

    def log_user_in(self, superuser=False):
        if superuser:
            user, pwd = self.superuser, self.su_pwd
        else:
            user, pwd = self.user, self.pwd
        response = self.client.post(reverse('login'),
                                    {'username': user.username, 'password': pwd},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["user"], user)

    # permissions redirects

    def test_user_list_redirect(self):
        self.login_redirect("users")
        self.log_user_in()
        self.permission_denied("users")

    def test_user_invite_redirect(self):
        self.login_redirect("invite_user")
        self.log_user_in()
        self.permission_denied("invite_user")

    def test_user_update_redirect(self):
        self.login_redirect("update_user", self.user.id)
        self.log_user_in()
        self.permission_denied("update_user", self.superuser.id)

    def test_user_delete_redirect(self):
        self.login_redirect("delete_user", self.user.id)
        self.log_user_in()
        self.permission_denied("delete_user", self.user.id)

    # user list

    def test_user_list_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("accounts:users"))
        for text in (self.user.username, self.user.email,
                     self.remoteuser.username, self.remoteuser.email,
                     self.superuser.username, self.superuser.email,
                     "3 Users",
                     reverse("accounts:delete_user", args=(self.user.pk,)),
                     reverse("accounts:update_user", args=(self.user.pk,)),
                     reverse("accounts:delete_user", args=(self.remoteuser.pk,)),
                     reverse("accounts:update_user", args=(self.remoteuser.pk,)),
                     reverse("accounts:update_user", args=(self.superuser.pk,))):
            self.assertContains(response, text)
        self.assertNotContains(response, reverse("accounts:delete_user", args=(self.superuser.pk,)))

    # invite

    def test_user_invite_get(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("accounts:invite_user"))
        self.assertContains(response, "Send an email invitation")

    def test_user_invite_username_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:invite_user"),
                                    {"username": self.user.username,
                                     "email": "test@example.com"},
                                    follow=True)
        self.assertFormError(response, "form", "username", "A user with that username already exists.")

    def test_user_invite_email_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:invite_user"),
                                    {"username": "test",
                                     "email": self.user.email},
                                    follow=True)
        self.assertFormError(response, "form", "email", "User with this Email already exists.")

    def test_user_invite_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:invite_user"),
                                    {"username": "test",
                                     "email": "test@example.com"},
                                    follow=True)
        for text in ("4 Users", "test", "test@example.com"):
            self.assertContains(response, text)

    # update

    def test_user_update_404(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("accounts:update_user", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_user_update_get(self):
        self.log_user_in(superuser=True)
        for user, ue_disabled, su_disabled in ((self.user, False, False),
                                               (self.remoteuser, True, False),
                                               (self.superuser, False, True)):
            response = self.client.get(reverse("accounts:update_user", args=(user.id,)))
            self.assertContains(response, "Update user {}".format(user))
            form = response.context["form"]
            self.assertEqual(form.fields["is_superuser"].disabled, su_disabled)
            self.assertEqual(form.fields["username"].disabled, ue_disabled)
            self.assertEqual(form.fields["email"].disabled, ue_disabled)

    def test_user_update_username_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:update_user", args=(self.user.id,)),
                                    {"username": self.superuser.username,
                                     "email": self.user.email,
                                     "is_superuser": self.user.is_superuser})
        self.assertFormError(response, "form", "username", "A user with that username already exists.")

    def test_user_update_email_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:update_user", args=(self.user.id,)),
                                    {"username": self.user.username,
                                     "email": self.superuser.email,
                                     "is_superuser": self.user.is_superuser})
        self.assertFormError(response, "form", "email", "User with this Email already exists.")

    def test_user_update_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:update_user", args=(self.user.id,)),
                                    {"username": "toto",
                                     "email": "tata@example.com",
                                     "is_superuser": self.user.is_superuser},
                                    follow=True)
        self.assertTemplateUsed(response, "accounts/user_detail.html")
        for text in ("User tata@example.com", "toto"):
            self.assertContains(response, text)

    # delete

    def test_user_delete_404(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:delete_user", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_superuser_delete_redirect(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("accounts:delete_user", args=(self.superuser.id,)))
        self.assertRedirects(response, reverse("accounts:users"))

    def test_user_delete_ok(self):
        self.log_user_in(superuser=True)
        user_str = str(self.user)
        response = self.client.post(reverse("accounts:delete_user", args=(self.user.id,)),
                                    follow=True)
        self.assertContains(response, "User {} deleted".format(user_str))
        self.assertContains(response, "2 User")
