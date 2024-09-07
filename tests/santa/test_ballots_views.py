from datetime import datetime, timedelta
from functools import reduce
from importlib import import_module
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.conf import settings
from django.db.models import Q
from django.http import HttpRequest
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from realms.backends.views import finalize_session
from realms.models import RealmAuthenticationSession
from zentral.contrib.santa.ballot_box import DuplicateVoteError, VotingNotAllowedError
from zentral.contrib.santa.models import Ballot, Target, TargetState
from .utils import add_file_to_test_class, force_ballot, force_configuration, force_realm, force_realm_user


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaBallotsViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.realm = force_realm(enabled_for_login=True)
        _, cls.realm_user = force_realm_user(realm=cls.realm, username=cls.user.username, email=cls.user.email)
        add_file_to_test_class(cls)
        cls.configuration = force_configuration(
            voting_realm=cls.realm,
            default_ballot_target_types=[Target.Type.METABUNDLE, Target.Type.BUNDLE, Target.Type.BINARY],
        )

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions, realm_user=False):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        if not realm_user:
            self.client.force_login(self.user)
        else:
            # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/test/client.py#L785  # NOQA
            request = HttpRequest()
            # HACK
            # see https://github.com/django/django/blob/705066d186ce880bf64142e47084f3d8df3c2352/django/contrib/auth/__init__.py#L141-L142  # NOQA
            # so that the user is attached to the request. The realm callback expects a user on the request!
            request.user = None
            if self.client.session:
                request.session = self.client.session
            else:
                engine = import_module(settings.SESSION_ENGINE)
                request.session = engine.SessionStore()
            ras = RealmAuthenticationSession.objects.create(
                realm=self.realm,
                callback="realms.utils.login_callback",
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

    # ballots

    def test_ballots_redirect(self):
        self._login_redirect(reverse("santa:ballots"))

    def test_ballots_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 403)

    def test_no_ballots_no_filters(self):
        self._login("santa.view_ballot")
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (0)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_ballots_no_filters(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 1)])
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")

    @patch("zentral.contrib.santa.views.ballots.BallotsView.get_paginate_by")
    def test_ballots_no_filters_next_page(self, get_paginate_by):
        get_paginate_by.return_value = 1
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 1)])
        force_ballot(self.bundle_target, self.realm_user, [(self.configuration, True, 1)])
        response = self.client.get(reverse("santa:ballots"), {"page": "yolo"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "page 1 of 2")

    @patch("zentral.contrib.santa.views.ballots.BallotsView.get_paginate_by")
    def test_ballots_no_filters_prev_page(self, get_paginate_by):
        get_paginate_by.return_value = 1
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 1)])
        force_ballot(self.bundle_target, self.realm_user, [(self.configuration, True, 1)])
        response = self.client.get(reverse("santa:ballots"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "page 2 of 2")

    def test_ballots_target_type_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, True, 934)])
        response = self.client.get(reverse("santa:ballots"), {"target_type": Target.Type.METABUNDLE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+934")
        self.assertNotContains(response, "+192")

    def test_ballots_target_identifier_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, True, 934)])
        response = self.client.get(reverse("santa:ballots"), {"target_identifier": self.metabundle_sha256})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+934")
        self.assertNotContains(response, "+192")

    def test_ballots_target_state_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, False, 934)])
        TargetState.objects.create(
            target=self.file_target,
            configuration=self.configuration,
            state=TargetState.State.GLOBALLY_ALLOWLISTED,
            score=192,
        )
        response = self.client.get(reverse("santa:ballots"), {"target_state": TargetState.State.GLOBALLY_ALLOWLISTED})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+192")
        self.assertNotContains(response, "-934")

    def test_ballots_configuration_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        configuration = force_configuration(voting_realm=self.realm)
        force_ballot(self.metabundle_target, self.realm_user, [(configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_realm_user_filter(self):
        _, realm_user2 = force_realm_user(realm=self.realm)
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, realm_user2, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"realm_user": realm_user2.username})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_yes_vote_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"include_yes_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+192")
        self.assertNotContains(response, "-934")

    def test_ballots_no_vote_filter(self):
        self._login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"include_no_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_revised_ballot_not_included(self):
        self._login("santa.view_ballot")
        ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.file_target, self.realm_user, [(self.configuration, False, 934)], replaced_by=ballot)
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+192")
        self.assertNotContains(response, "-934")

    def test_ballots_revised_ballot_included(self):
        self._login("santa.view_ballot")
        ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.file_target, self.realm_user, [(self.configuration, False, 934)], replaced_by=ballot)
        response = self.client.get(reverse("santa:ballots"), {"include_revised_ballots": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_reset_ballot_not_included(self):
        self._login("santa.view_ballot")
        reset_ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        reset_ballot.created_at -= timedelta(days=10)
        reset_ballot.save()
        reset_ballot.vote_set.update(created_at=reset_ballot.created_at)
        TargetState.objects.create(
            target=self.file_target,
            configuration=self.configuration,
            state=TargetState.State.UNTRUSTED,
            score=0,
            reset_at=datetime.now()
        )
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 193)])
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "+193")

    def test_ballots_reset_ballot_included(self):
        self._login("santa.view_ballot")
        reset_ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        reset_ballot.created_at -= timedelta(days=10)
        reset_ballot.save()
        reset_ballot.vote_set.update(created_at=reset_ballot.created_at)
        TargetState.objects.create(
            target=self.file_target,
            configuration=self.configuration,
            state=TargetState.State.UNTRUSTED,
            score=0,
            reset_at=datetime.now()
        )
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 193)])
        response = self.client.get(reverse("santa:ballots"), {"include_reset_ballots": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "+192")
        self.assertContains(response, "+193")

    def test_ballots_todo_filter(self):
        _, realm_user2 = force_realm_user(realm=self.realm)
        self._login("santa.view_ballot")
        TargetState.objects.create(
            target=self.file_target,
            configuration=self.configuration,
            state=TargetState.State.UNTRUSTED,
            score=0,
            reset_at=datetime.now() - timedelta(days=1)
        )
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, realm_user2, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"todo": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    # cast ballot

    def test_cast_ballot_redirect(self):
        self._login_redirect(reverse("santa:cast_ballot"))

    def test_cast_ballot_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cast_ballot"))
        self.assertEqual(response.status_code, 403)

    def test_cast_ballot_no_target(self):
        self._login("santa.add_ballot")
        response = self.client.get(reverse("santa:cast_ballot"))
        self.assertEqual(response.status_code, 404)

    def test_cast_ballot_file_target_no_realm_user(self):
        self._login("santa.add_ballot")
        response = self.client.get(reverse("santa:cast_ballot"),
                                   {"target_type": self.file_target.type,
                                    "target_identifier": self.file_target.identifier})
        self.assertEqual(response.status_code, 403)

    def test_cast_ballot_get(self):
        self._login("santa.add_ballot", realm_user=True)
        response = self.client.get(reverse("santa:cast_ballot"),
                                   {"target_type": self.file_target.type,
                                    "target_identifier": self.file_target.identifier})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")

    def test_cast_ballot_post_form_error(self):
        ballot_qs = Ballot.objects.filter(target=self.bundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BUNDLE&target_identifier={self.bundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "NO"},  # no vote on bundle → error
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")
        self.assertContains(response, "Invalid ballot")
        self.assertEqual(ballot_qs.count(), 0)

    def test_cast_ballot_post_empty_ballot(self):
        ballot_qs = Ballot.objects.filter(target=self.bundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BUNDLE&target_identifier={self.bundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "NOVOTE"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")
        self.assertContains(response, "Empty ballot")
        self.assertEqual(ballot_qs.count(), 0)

    @patch("zentral.contrib.santa.views.ballots.BallotBox.cast_votes")
    def test_cast_ballot_post_duplicate_vote(self, cast_votes):
        cast_votes.side_effect = DuplicateVoteError
        ballot_qs = Ballot.objects.filter(target=self.bundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BUNDLE&target_identifier={self.bundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "YES"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")
        self.assertContains(response, "You cannot cast the same ballot twice")
        self.assertEqual(ballot_qs.count(), 0)

    @patch("zentral.contrib.santa.views.ballots.BallotBox.cast_votes")
    def test_cast_ballot_post_voting_not_allowed(self, cast_votes):
        cast_votes.side_effect = VotingNotAllowedError
        ballot_qs = Ballot.objects.filter(target=self.bundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BUNDLE&target_identifier={self.bundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "YES"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")
        self.assertContains(response, "The ballot was rejected")
        self.assertEqual(ballot_qs.count(), 0)

    def test_cast_ballot_post_yes(self):
        ballot_qs = Ballot.objects.filter(target=self.metabundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", "santa.view_target", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=METABUNDLE&target_identifier={self.metabundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "YES"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertEqual(ballot_qs.count(), 1)

    def test_cast_ballot_post_no(self):
        ballot_qs = Ballot.objects.filter(target=self.file_target)
        self.assertEqual(ballot_qs.count(), 0)
        self._login("santa.add_ballot", "santa.view_target", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BINARY&target_identifier={self.file_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "NO"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertEqual(ballot_qs.count(), 1)
