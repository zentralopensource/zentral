from datetime import datetime, timedelta
from unittest.mock import patch
from django.contrib.auth.models import Group
from django.urls import reverse
from django.test import TestCase
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.santa.ballot_box import DuplicateVoteError, VotingNotAllowedError
from zentral.contrib.santa.events import SantaBallotEvent, SantaTargetStateUpdateEvent
from zentral.contrib.santa.models import Ballot, Target, TargetState
from .utils import add_file_to_test_class, force_ballot, force_configuration, force_realm, force_realm_user


class SantaBallotsViewsTestCase(TestCase, LoginCase):
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
            default_voting_weight=1,
        )

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "santa"

    def _get_realm(self):
        return self.realm

    def _get_realm_user(self):
        return self.realm_user

    # ballots

    def test_ballots_redirect(self):
        self.login_redirect("ballots")

    def test_ballots_permission_denied(self):
        self.login()
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 403)

    def test_no_ballots_no_filters(self):
        self.login("santa.view_ballot")
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (0)")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_ballots_no_filters(self):
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 1)])
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")

    @patch("zentral.contrib.santa.views.ballots.BallotsView.get_paginate_by")
    def test_ballots_no_filters_next_page(self, get_paginate_by):
        get_paginate_by.return_value = 1
        self.login("santa.view_ballot")
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
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 1)])
        force_ballot(self.bundle_target, self.realm_user, [(self.configuration, True, 1)])
        response = self.client.get(reverse("santa:ballots"), {"page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "page 2 of 2")

    def test_ballots_target_type_filter(self):
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, True, 934)])
        response = self.client.get(reverse("santa:ballots"), {"target_type": Target.Type.METABUNDLE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+934")
        self.assertNotContains(response, "+192")

    def test_ballots_target_identifier_filter(self):
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, True, 934)])
        response = self.client.get(reverse("santa:ballots"), {"target_identifier": self.metabundle_sha256})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+934")
        self.assertNotContains(response, "+192")

    def test_ballots_target_state_filter(self):
        self.login("santa.view_ballot")
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
        self.login("santa.view_ballot")
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
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, realm_user2, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"realm_user": realm_user2.username})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_yes_vote_filter(self):
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"include_yes_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+192")
        self.assertNotContains(response, "-934")

    def test_ballots_no_vote_filter(self):
        self.login("santa.view_ballot")
        force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.metabundle_target, self.realm_user, [(self.configuration, False, 934)])
        response = self.client.get(reverse("santa:ballots"), {"include_no_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertNotContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_revised_ballot_not_included(self):
        self.login("santa.view_ballot")
        ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.file_target, self.realm_user, [(self.configuration, False, 934)], replaced_by=ballot)
        response = self.client.get(reverse("santa:ballots"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballot (1)")
        self.assertContains(response, "+192")
        self.assertNotContains(response, "-934")

    def test_ballots_revised_ballot_included(self):
        self.login("santa.view_ballot")
        ballot = force_ballot(self.file_target, self.realm_user, [(self.configuration, True, 192)])
        force_ballot(self.file_target, self.realm_user, [(self.configuration, False, 934)], replaced_by=ballot)
        response = self.client.get(reverse("santa:ballots"), {"include_revised_ballots": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballots.html")
        self.assertContains(response, "Ballots (2)")
        self.assertContains(response, "+192")
        self.assertContains(response, "-934")

    def test_ballots_reset_ballot_not_included(self):
        self.login("santa.view_ballot")
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
        self.login("santa.view_ballot")
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
        self.login("santa.view_ballot")
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
        self.login_redirect("cast_ballot")

    def test_cast_ballot_permission_denied(self):
        self.login()
        response = self.client.get(reverse("santa:cast_ballot"))
        self.assertEqual(response.status_code, 403)

    def test_cast_ballot_no_target(self):
        self.login("santa.add_ballot")
        response = self.client.get(reverse("santa:cast_ballot"))
        self.assertEqual(response.status_code, 404)

    def test_cast_ballot_file_target_no_realm_user(self):
        self.login("santa.add_ballot")
        response = self.client.get(reverse("santa:cast_ballot"),
                                   {"target_type": self.file_target.type,
                                    "target_identifier": self.file_target.identifier})
        self.assertEqual(response.status_code, 403)

    def test_cast_ballot_get(self):
        self.login("santa.add_ballot", realm_user=True)
        response = self.client.get(reverse("santa:cast_ballot"),
                                   {"target_type": self.file_target.type,
                                    "target_identifier": self.file_target.identifier})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")

    def test_cast_ballot_post_form_error(self):
        ballot_qs = Ballot.objects.filter(target=self.bundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self.login("santa.add_ballot", realm_user=True)
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
        self.login("santa.add_ballot", realm_user=True)
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
        self.login("santa.add_ballot", realm_user=True)
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
        self.login("santa.add_ballot", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BUNDLE&target_identifier={self.bundle_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "YES"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/ballot_form.html")
        self.assertContains(response, "The ballot was rejected")
        self.assertEqual(ballot_qs.count(), 0)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_cast_ballot_post_yes(self, post_event):
        ballot_qs = Ballot.objects.filter(target=self.metabundle_target)
        self.assertEqual(ballot_qs.count(), 0)
        self.login("santa.add_ballot", "santa.view_target", realm_user=True)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("santa:cast_ballot")
                                        + f"?target_type=METABUNDLE&target_identifier={self.metabundle_sha256}",
                                        {f"cfg-{self.configuration.pk}-yes_no": "YES"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertEqual(ballot_qs.count(), 1)
        self.assertEqual(len(post_event.call_args_list), 3)
        event1 = post_event.call_args_list[1].args[0]
        self.assertIsInstance(event1, SantaBallotEvent)
        self.assertEqual(len(event1.payload["votes"]), 1)
        self.assertTrue(event1.payload["votes"][0]["was_yes_vote"])
        self.assertEqual(event1.payload["votes"][0]["weight"], 1)
        event2 = post_event.call_args_list[2].args[0]
        self.assertIsInstance(event2, SantaTargetStateUpdateEvent)
        self.assertEqual(event2.payload["new_value"]["score"], 1)
        self.assertEqual(event2.payload["prev_value"]["score"], 0)

    def test_cast_ballot_post_no(self):
        ballot_qs = Ballot.objects.filter(target=self.file_target)
        self.assertEqual(ballot_qs.count(), 0)
        self.login("santa.add_ballot", "santa.view_target", realm_user=True)
        response = self.client.post(reverse("santa:cast_ballot")
                                    + f"?target_type=BINARY&target_identifier={self.file_sha256}",
                                    {f"cfg-{self.configuration.pk}-yes_no": "NO"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, "Your ballot has been cast")
        self.assertEqual(ballot_qs.count(), 1)
