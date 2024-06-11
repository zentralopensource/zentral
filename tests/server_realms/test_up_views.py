from importlib import import_module
from django.conf import settings
from django.http import HttpRequest
from django.test import TestCase, override_settings
from django.urls import reverse
from realms.backends.views import finalize_session
from realms.models import RealmAuthenticationSession
from .utils import force_realm, force_realm_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.realm, cls.realm_user = force_realm_user(realm=force_realm(user_portal=True))

    # utility methods

    def _login(self, realm_user=None):

        # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/test/client.py#L785  # NOQA
        request = HttpRequest()
        if self.client.session:
            request.session = self.client.session
        else:
            engine = import_module(settings.SESSION_ENGINE)
            request.session = engine.SessionStore()
        if realm_user:
            realm = realm_user.realm
            # take this opportunity to add a current ras to the request, with a different realm
            request.realm_authentication_session = RealmAuthenticationSession.objects.create(
                realm=self.realm,
                user=self.realm_user,
                callback="realms.up_views.login_callback",
            )
        else:
            realm = self.realm
            realm_user = self.realm_user
        ras = RealmAuthenticationSession.objects.create(
            realm=realm,
            callback="realms.up_views.login_callback",
        )
        finalize_session(ras, request, realm_user)
        request.session.save()
        session_cookie = settings.SESSION_COOKIE_NAME
        self.client.cookies[session_cookie] = request.session.session_key
        cookie_data = {
            "max-age": None,
            "path": "/",
            "domain": settings.SESSION_COOKIE_DOMAIN,
            "secure": settings.SESSION_COOKIE_SECURE or None,
            "expires": None,
        }
        self.client.cookies[session_cookie].update(cookie_data)

    def _assert_redirect_to_login(self, url):
        response = self.client.get(url)
        ras = RealmAuthenticationSession.objects.get(realm=self.realm, user__isnull=True)
        self.assertRedirects(response, reverse("realms_public:ldap_login", args=(self.realm.pk, ras.pk)))

    # index

    def test_no_up_index(self):
        realm = force_realm(user_portal=False)
        response = self.client.get(reverse("realms_public:up_index", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_up_index_redirect(self):
        self._assert_redirect_to_login(reverse("realms_public:up_index", args=(self.realm.pk,)))

    def test_wrong_realm_redirect(self):
        realm, realm_user = force_realm_user(realm=force_realm(user_portal=True))
        self._login(realm_user)
        self._assert_redirect_to_login(reverse("realms_public:up_index", args=(self.realm.pk,)))

    def test_realm_user_inactive_redirect(self):
        _, realm_user = force_realm_user(realm=self.realm)
        realm_user.scim_external_id = "yolo"
        realm_user.scim_active = False
        realm_user.save()
        self._login(realm_user)
        self._assert_redirect_to_login(reverse("realms_public:up_index", args=(self.realm.pk,)))

    def test_up_index(self):
        self._login()
        response = self.client.get(reverse("realms_public:up_index", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/index.html")

    # logout

    def test_no_up_logout(self):
        realm = force_realm(user_portal=False)
        response = self.client.get(reverse("realms_public:up_logout", args=(realm.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_up_logout(self):
        self._login()
        self.assertIn("realm_authentication_session", self.client.session)
        response = self.client.post(reverse("realms_public:up_logout", args=(self.realm.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/logout.html")
        self.assertNotIn("realm_authentication_session", self.client.session)
