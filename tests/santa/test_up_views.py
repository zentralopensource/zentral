from datetime import datetime
from importlib import import_module
import uuid
from django.conf import settings
from django.http import HttpRequest
from django.urls import reverse
from django.test import TestCase, override_settings
from realms.backends.views import finalize_session
from realms.models import RealmAuthenticationSession
from zentral.contrib.santa.ballot_box import BallotBox
from zentral.contrib.santa.models import Ballot, Target
from .utils import add_file_to_test_class, force_configuration, force_enrolled_machine, force_realm, force_realm_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.realm, cls.realm_user = force_realm_user(realm=force_realm(user_portal=True))
        cls.configuration = force_configuration(
            voting_realm=cls.realm,
            default_ballot_target_types=[Target.Type.METABUNDLE, Target.Type.SIGNING_ID],
        )
        cls.em = force_enrolled_machine(
            configuration=cls.configuration,
            primary_user=cls.realm_user.username,
            last_seen=datetime.utcnow(),
        )
        add_file_to_test_class(cls)

    # utility methods

    def _login(self):
        # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/test/client.py#L785  # NOQA
        request = HttpRequest()
        if self.client.session:
            request.session = self.client.session
        else:
            engine = import_module(settings.SESSION_ENGINE)
            request.session = engine.SessionStore()
        ras = RealmAuthenticationSession.objects.create(
            realm=self.realm,
            callback="realms.up_views.login_callback",
        )
        finalize_session(ras, request, self.realm_user)
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

    # event detail

    def test_event_detail_redirect(self):
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)))
        ras = RealmAuthenticationSession.objects.get(realm=self.realm, user__isnull=True)
        self.assertRedirects(response, reverse("realms_public:ldap_login", args=(self.realm.pk, ras.pk)))

    def test_event_detail_file_redirect_to_binary_target(self):
        self._login()
        mid = str(uuid.uuid4())
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": self.file_sha256,
                                    "bofid": self.file_sha256,
                                    "mid": mid})
        self.assertRedirects(
            response,
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256)),
        )
        self.assertEqual(self.client.session["_up_santa_etid"], self.file_sha256)
        self.assertEqual(self.client.session["_up_santa_mid"], mid)

    def test_event_detail_file_redirect_to_binary_target_no_mid(self):
        self._login()
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": self.file_sha256,
                                    "bofid": self.file_sha256})
        self.assertRedirects(
            response,
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256)),
        )
        self.assertEqual(self.client.session["_up_santa_etid"], self.file_sha256)
        self.assertNotIn("_up_santa_mid", self.client.session)

    def test_event_detail_file_redirect_to_bundle_target(self):
        self._login()
        mid = str(uuid.uuid4())
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": self.file_sha256,
                                    "bofid": self.bundle_sha256,
                                    "mid": mid})
        self.assertRedirects(
            response,
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "bundle", self.bundle_sha256)),
        )
        self.assertEqual(self.client.session["_up_santa_etid"], self.file_sha256)
        self.assertEqual(self.client.session["_up_santa_mid"], mid)

    def test_event_detail_empty_fid(self):
        self._login()
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"bofid": self.bundle_sha256})
        self.assertEqual(response.status_code, 400)

    def test_event_detail_invalid_fid(self):
        self._login()
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": "yolo",
                                    "bofid": self.bundle_sha256})
        self.assertEqual(response.status_code, 400)

    def test_event_detail_empty_bofid(self):
        self._login()
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": self.file_sha256})
        self.assertEqual(response.status_code, 400)

    def test_event_detail_invalid_bofid(self):
        self._login()
        response = self.client.get(reverse("realms_public:santa_up:event_detail", args=(self.realm.pk,)),
                                   {"fid": self.file_sha256,
                                    "bofid": "yolo"})
        self.assertEqual(response.status_code, 400)

    # target

    def test_target_redirect(self):
        response = self.client.get(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256))
        )
        ras = RealmAuthenticationSession.objects.get(realm=self.realm, user__isnull=True)
        self.assertRedirects(response, reverse("realms_public:ldap_login", args=(self.realm.pk, ras.pk)))

    def test_target_get_file_signing_id_ballot_box(self):
        self._login()
        session = self.client.session
        session["_up_santa_mid"] = str(self.em.hardware_uuid)
        session.save()
        response = self.client.get(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Vote to allowlist")
        self.assertContains(response, "Vote to blocklist")
        ballot_box = response.context["ballot_box"]
        self.assertEqual(ballot_box.target.type, Target.Type.SIGNING_ID)
        self.assertEqual(ballot_box.target.identifier, self.file_signing_id)
        self.assertEqual(response.context["current_machine"].serial_number, self.em.serial_number)
        self.assertEqual(response.context["current_configuration"], self.configuration)

    def test_target_post_file_signing_id_ballot_box_yes(self):
        self._login()
        ballot_qs = Ballot.objects.filter(realm_user=self.realm_user,
                                          target__type=Target.Type.SIGNING_ID,
                                          target__identifier=self.file_signing_id)
        self.assertEqual(ballot_qs.count(), 0)
        response = self.client.post(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256)),
            {"yes_vote": "oui"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertNotContains(response, "Vote to allowlist")
        self.assertContains(response, "Vote to blocklist")
        self.assertEqual(
            response.context["existing_votes"],
            [(self.configuration, True)],
        )
        self.assertEqual(ballot_qs.count(), 1)
        ballot = ballot_qs.first()
        self.assertIsNone(ballot.event_target)

    def test_target_post_file_signing_id_ballot_box_no(self):
        self._login()
        ballot_qs = Ballot.objects.filter(realm_user=self.realm_user,
                                          target__type=Target.Type.SIGNING_ID,
                                          target__identifier=self.file_signing_id)
        self.assertEqual(ballot_qs.count(), 0)
        session = self.client.session  # HACK, if modified directly in the client this doesn't work!
        session["_up_santa_etid"] = self.file_sha256
        session.save()
        response = self.client.post(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "binary", self.file_sha256)),
            {"yes_vote": "non"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertNotContains(response, "Vote to allowlist")
        self.assertNotContains(response, "Vote to blocklist")
        self.assertEqual(
            response.context["existing_votes"],
            [(self.configuration, False)],
        )
        self.assertEqual(ballot_qs.count(), 1)
        ballot = ballot_qs.first()
        self.assertEqual(ballot.event_target, self.file_target)

    def test_target_get_bundle_metabundle_ballot_box(self):
        self._login()
        response = self.client.get(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "bundle", self.bundle_sha256))
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Vote to allowlist")
        self.assertNotContains(response, "Vote to blocklist")
        ballot_box = response.context["ballot_box"]
        self.assertEqual(ballot_box.target.type, Target.Type.METABUNDLE)
        self.assertEqual(ballot_box.target.identifier, self.metabundle_sha256)

    def test_target_post_bundle_metabundle_ballot_box_yes(self):
        self._login()
        response = self.client.post(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "bundle", self.bundle_sha256)),
            {"yes_vote": "oui"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertNotContains(response, "Vote to allowlist")
        self.assertNotContains(response, "Vote to blocklist")
        self.assertEqual(
            response.context["existing_votes"],
            [(self.configuration, True)],
        )

    def test_target_post_bundle_metabundle_ballot_box_yolo(self):
        self._login()
        response = self.client.post(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "bundle", self.bundle_sha256)),
            {"yes_vote": "yolo"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "Invalid request")
        self.assertContains(response, "Vote to allowlist")
        self.assertNotContains(response, "Vote to blocklist")
        self.assertEqual(response.context["existing_votes"], [])

    def test_target_post_file_signing_id_ballot_box_yes_duplicate(self):
        self._login()
        ballot_box = BallotBox.for_realm_user(self.metabundle_target, self.realm_user)
        ballot_box.cast_default_votes(True, self.file_target)
        response = self.client.post(
            reverse("realms_public:santa_up:target",
                    args=(self.realm.pk, "bundle", self.bundle_sha256)),
            {"yes_vote": "oui"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "user_portal/santa_target_detail.html")
        self.assertContains(response, "You cannot cast the same ballot twice")
        self.assertNotContains(response, "Vote to allowlist")
        self.assertNotContains(response, "Vote to blocklist")
        self.assertEqual(
            response.context["existing_votes"],
            [(self.configuration, True)],
        )
