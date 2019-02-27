from django.urls import reverse
from django.test import TestCase, override_settings
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class AccountUsersViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # superuser
        cls.su_pwd = "godzillapwd"
        cls.superuser = User.objects.create_user("godzilla", "godzilla@zentral.io", cls.su_pwd,
                                                 is_superuser=True)
        # user
        cls.pwd = "yo"
        cls.user = User.objects.create_user("yo", "yo@zentral.io", cls.pwd)
        # remote user
        cls.remoteuser = User.objects.create_user("remote", "remote@zentral.io", "remote",
                                                  is_remote=True)

    # auth utils

    def login_redirect(self, url_name, *args):
        url = reverse("users:{}".format(url_name), args=args)
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def permission_denied(self, url_name, *args):
        url = reverse("users:{}".format(url_name), args=args)
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
        self.login_redirect("list")
        self.log_user_in()
        self.permission_denied("list")

    def test_user_add_redirect(self):
        self.login_redirect("add")
        self.log_user_in()
        self.permission_denied("add")

    def test_user_update_redirect(self):
        self.login_redirect("update", self.user.id)
        self.log_user_in()
        self.permission_denied("update", self.superuser.id)

    def test_user_delete_redirect(self):
        self.login_redirect("delete", self.user.id)
        self.log_user_in()
        self.permission_denied("delete", self.user.id)

    # user list

    def test_user_list_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("users:list"))
        for text in (self.user.username, self.user.email,
                     self.remoteuser.username, self.remoteuser.email,
                     self.superuser.username, self.superuser.email,
                     "3 Users",
                     reverse("users:delete", args=(self.user.pk,)),
                     reverse("users:update", args=(self.user.pk,)),
                     reverse("users:delete", args=(self.remoteuser.pk,)),
                     reverse("users:update", args=(self.remoteuser.pk,)),
                     reverse("users:update", args=(self.superuser.pk,))):
            self.assertContains(response, text)
        self.assertNotContains(response, reverse("users:delete", args=(self.superuser.pk,)))

    # add

    def test_user_add_get(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("users:add"))
        self.assertContains(response, "Send an email invitation")

    def test_user_add_username_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:add"),
                                    {"username": self.user.username,
                                     "email": "test@example.com"},
                                    follow=True)
        self.assertFormError(response, "form", "username", "A user with that username already exists.")

    def test_user_add_email_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:add"),
                                    {"username": "test",
                                     "email": self.user.email},
                                    follow=True)
        self.assertFormError(response, "form", "email", "User with this Email already exists.")

    def test_user_add_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:add"),
                                    {"username": "test",
                                     "email": "test@example.com"},
                                    follow=True)
        for text in ("4 Users", "test", "test@example.com"):
            self.assertContains(response, text)

    # update

    def test_user_update_404(self):
        self.log_user_in(superuser=True)
        response = self.client.get(reverse("users:update", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_user_update_get(self):
        self.log_user_in(superuser=True)
        for user, ue_disabled, su_disabled in ((self.user, False, False),
                                               (self.remoteuser, True, False),
                                               (self.superuser, False, True)):
            response = self.client.get(reverse("users:update", args=(user.id,)))
            self.assertContains(response, "Update user {}".format(user))
            form = response.context["form"]
            self.assertEqual(form.fields["is_superuser"].disabled, su_disabled)
            self.assertEqual(form.fields["username"].disabled, ue_disabled)
            self.assertEqual(form.fields["email"].disabled, ue_disabled)

    def test_user_update_username_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:update", args=(self.user.id,)),
                                    {"username": self.superuser.username,
                                     "email": self.user.email,
                                     "is_superuser": self.user.is_superuser})
        self.assertFormError(response, "form", "username", "A user with that username already exists.")

    def test_user_update_email_error(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:update", args=(self.user.id,)),
                                    {"username": self.user.username,
                                     "email": self.superuser.email,
                                     "is_superuser": self.user.is_superuser})
        self.assertFormError(response, "form", "email", "User with this Email already exists.")

    def test_user_update_ok(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:update", args=(self.user.id,)),
                                    {"username": "toto",
                                     "email": "tata@example.com",
                                     "is_superuser": self.user.is_superuser},
                                    follow=True)
        for text in ("3 Users", "toto", "tata@example.com"):
            self.assertContains(response, text)
        self.assertNotContains(response, self.user.username)

    # delete

    def test_user_delete_404(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:delete", args=(0,)))
        self.assertEqual(response.status_code, 404)

    def test_superuser_delete_redirect(self):
        self.log_user_in(superuser=True)
        response = self.client.post(reverse("users:delete", args=(self.superuser.id,)))
        self.assertRedirects(response, reverse("users:list"))

    def test_user_delete_ok(self):
        self.log_user_in(superuser=True)
        user_str = str(self.user)
        response = self.client.post(reverse("users:delete", args=(self.user.id,)),
                                    follow=True)
        self.assertContains(response, "User {} deleted".format(user_str))
        self.assertContains(response, "2 User")
