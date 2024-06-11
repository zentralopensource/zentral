from datetime import datetime, timedelta
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.santa.ballot_box import (AnonymousVoter, BallotBox, DuplicateVoteError,
                                              Voter, VotingError, VotingNotAllowedError)
from zentral.contrib.santa.models import Rule, Target, TargetState
from .utils import (add_file_to_test_class, force_ballot, force_configuration, force_enrolled_machine,
                    force_realm_user, force_target, force_voting_group)


class SantaBallotBoxTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        add_file_to_test_class(cls)

    # Voter

    def test_voter_realm_groups(self):
        _, realm_user = force_realm_user()
        voter = Voter(realm_user)
        self.assertEqual(voter.realm_groups, [])

    def test_voter_enrolled_machines(self):
        _, realm_user = force_realm_user()
        now = datetime.utcnow()
        to_old = now - timedelta(days=46)
        force_enrolled_machine(primary_user=get_random_string(12), last_seen=now)
        em = force_enrolled_machine(primary_user=realm_user.username, last_seen=now)
        force_enrolled_machine(primary_user=realm_user.username, last_seen=to_old)
        voter = Voter(realm_user, max_machine_age_days=45)
        self.assertEqual(voter.enrolled_machines, [(em, now)])

    def test_voter_configurations(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        configuration2 = force_configuration()
        now = datetime.utcnow()
        force_enrolled_machine(primary_user=realm_user.username, last_seen=now, configuration=configuration)
        force_enrolled_machine(primary_user=realm_user.username, last_seen=now, configuration=configuration2)
        voter = Voter(realm_user)
        self.assertEqual(voter.configurations, [configuration])

    def test_voter_all_configurations(self):
        force_configuration()  # not included
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)  # included because of the voting realm
        configuration2 = force_configuration()  # included because of a voting group
        force_voting_group(configuration2, realm_user)
        voter = Voter(realm_user, all_configurations=True)
        self.assertEqual(voter.configurations, sorted([configuration, configuration2], key=lambda c: c.name))

    def test_voter_voting_groups(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voting_group = force_voting_group(configuration, realm_user)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertEqual(voter.voting_groups, [voting_group])

    def test_voter_can_vote_on_target_type(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.METABUNDLE])
        force_voting_group(configuration, realm_user, ballot_target_types=[Target.Type.SIGNING_ID])
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertTrue(voter.can_vote_on_target_type(configuration, Target.Type.METABUNDLE))
        self.assertTrue(voter.can_vote_on_target_type(configuration, Target.Type.SIGNING_ID))
        self.assertFalse(voter.can_vote_on_target_type(configuration, Target.Type.BUNDLE))

    def test_voter_voting_weight_configuration(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_voting_weight=17)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertEqual(voter.voting_weight(configuration), 17)

    def test_voter_voting_weight_voting_group(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_voting_group(configuration, realm_user, voting_weight=42)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertEqual(voter.voting_weight(configuration), 42)

    def test_voter_can_mark_malware(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertFalse(voter.can_mark_malware(configuration))
        force_voting_group(configuration, realm_user, can_mark_malware=True)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertTrue(voter.can_mark_malware(configuration))

    def test_voter_can_unflag_target(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertFalse(voter.can_unflag_target(configuration))
        force_voting_group(configuration, realm_user, can_unflag_target=True)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertTrue(voter.can_unflag_target(configuration))

    def test_voter_can_reset_target(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertFalse(voter.can_reset_target(configuration))
        force_voting_group(configuration, realm_user, can_reset_target=True)
        voter = Voter(realm_user, all_configurations=True)  # to get the config without having to create EM
        self.assertTrue(voter.can_reset_target(configuration))

    def test_anonymous_voter(self):
        target = force_target()
        ballot_box = BallotBox.for_realm_user(target, None)
        voter = ballot_box.voter
        self.assertIsInstance(voter, AnonymousVoter)
        self.assertTrue(voter.is_anonymous)
        self.assertIsNone(voter.realm_user)
        self.assertEqual(voter.realm_groups, [])
        self.assertEqual(voter.voting_groups, [])
        self.assertEqual(voter.configurations, [])
        self.assertEqual(voter.enrolled_machines, [])
        configuration = force_configuration()
        self.assertFalse(voter.can_vote_on_target_type(configuration, Target.Type.METABUNDLE))
        self.assertEqual(voter.voting_weight(configuration), 0)
        self.assertFalse(voter.can_mark_malware(configuration))
        self.assertFalse(voter.can_unflag_target(configuration))
        self.assertFalse(voter.can_reset_target(configuration))

    # BallotBox

    def test_ballot_box_init_with_realm_user(self):
        target = force_target()
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ts_qs = TargetState.objects.filter(target=target, configuration=configuration)
        self.assertEqual(ts_qs.count(), 0)
        ballot_box = BallotBox.for_realm_user(
            target,
            realm_user,
            lock_target=False,
            all_configurations=True,  # to not have to create EMs
        )
        self.assertEqual(ballot_box.voter.realm_user, realm_user)
        self.assertFalse(ballot_box.voter.is_anonymous)
        self.assertEqual(ts_qs.count(), 1)
        ts = ts_qs.first()
        self.assertEqual(ts.state, TargetState.State.UNTRUSTED)
        self.assertEqual(ballot_box.target_states, {configuration: ts})

    def test_ballot_box_related_targets(self):
        related_targets = BallotBox.for_realm_user(self.file_target, None).related_targets
        self.assertEqual(set(related_targets.keys()),
                         {"TEAMID", "SIGNINGID", "CERTIFICATE", "CDHASH", "BINARY", "BUNDLE", "METABUNDLE"})

    def test_ballot_box_best_ballot_box_signing_id(self):
        realm, realm_user = force_realm_user()
        force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[
                Target.Type.METABUNDLE, Target.Type.SIGNING_ID
            ]
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        best_ballot_box = ballot_box.best_ballot_box()
        self.assertEqual(best_ballot_box.target.type, Target.Type.SIGNING_ID)
        self.assertEqual(best_ballot_box.target.identifier, self.file_signing_id)

    def test_ballot_box_best_ballot_box_metabundle(self):
        realm, realm_user = force_realm_user()
        force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[
                Target.Type.METABUNDLE, Target.Type.SIGNING_ID
            ]
        )
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        best_ballot_box = ballot_box.best_ballot_box()
        self.assertEqual(best_ballot_box.target.type, Target.Type.METABUNDLE)
        self.assertEqual(best_ballot_box.target.identifier, self.metabundle_sha256)

    def test_ballot_box_no_best_ballot_box(self):
        realm, realm_user = force_realm_user()
        force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[
                Target.Type.METABUNDLE,  # no signing id
            ]
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        self.assertIsNone(ballot_box.best_ballot_box())

    def test_ballot_box_target_info(self):
        target_info = BallotBox.for_realm_user(self.file_target, None).target_info()
        self.assertEqual(target_info["identifier"], self.file_sha256)

    def test_ballot_box_unknown_target_info(self):
        target = force_target()
        self.assertIsNone(BallotBox.for_realm_user(target, None).target_info())

    def test_ballot_box_publisher_info_team_id(self):
        publisher_info = BallotBox.for_realm_user(self.file_target, None).publisher_info()
        self.assertEqual(publisher_info, {'name': 'Apple Inc.', 'team_id': self.file_team_id})

    def test_ballot_box_publisher_info_certificated(self):
        ballot_box = BallotBox.for_realm_user(self.file_target, None)
        related_targets = ballot_box.related_targets
        related_targets.pop(Target.Type.CERTIFICATE)  # simulate no cert info
        publisher_info = ballot_box.publisher_info()
        self.assertEqual(publisher_info, {'name': 'Apple Inc.', 'team_id': self.file_team_id})

    def test_ballot_box_existing_ballot_anonymous_voter(self):
        self.assertIsNone(BallotBox.for_realm_user(self.file_target, None).existing_ballot)

    def test_ballot_box_existing_ballot_no_ballot(self):
        _, realm_user = force_realm_user()
        self.assertIsNone(BallotBox.for_realm_user(self.file_target, realm_user).existing_ballot)

    def test_ballot_box_existing_ballot(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ballot = force_ballot(self.file_target, realm_user, ((configuration, True, 17),))
        self.assertEqual(BallotBox.for_realm_user(self.file_target, realm_user).existing_ballot, ballot)

    def test_ballot_box_existing_votes_empty(self):
        self.assertEqual(BallotBox.for_realm_user(self.file_target, None).existing_votes, set())

    def test_ballot_box_existing_votes(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_ballot(self.file_target, realm_user, ((configuration, True, 17),))
        self.assertEqual(BallotBox.for_realm_user(self.file_target, realm_user).existing_votes,
                         {(configuration, True)})

    def test_ballot_box_check_voting_allowed_for_configuration_anonymous_voter(self):
        ballot_box = BallotBox.for_realm_user(self.file_target, None)
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(None, True),
                         "Anonymous voter")

    def test_ballot_box_check_voting_allowed_for_configuration_no_link_to_configuration(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user)
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "No link to configuration")

    def test_ballot_box_check_voting_allowed_for_configuration_target_is_banned(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ts = ballot_box.target_states[configuration]
        ts.state = TargetState.State.BANNED  # simulate banned target
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "Target is banned")

    def test_ballot_box_check_voting_allowed_for_configuration_target_is_globally_allowlisted(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ts = ballot_box.target_states[configuration]
        ts.state = TargetState.State.GLOBALLY_ALLOWLISTED  # simulate globally allowlisted target
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "Target is globally allowlisted")

    def test_ballot_box_check_voting_allowed_for_configuration_missing_bundle_information(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        self.bundle_target.bundle.uploaded_at = None  # simulate a bundle that is not ready
        self.bundle_target.bundle.save()
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "Missing bundle information")

    def test_ballot_box_check_voting_allowed_for_configuration_contains_a_flagged_target(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        configuration2 = force_configuration(voting_realm=realm)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        ballot_box.related_targets[Target.Type.BINARY][self.file_sha256]["states"] = [
            {"pk": configuration2.pk,
             "flagged": False},  # binary not flagged in second configuration
            {"pk": configuration.pk,
             "flagged": True},  # contains a flagged binary
        ]
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "The target contains a flagged BINARY target")

    def test_ballot_box_check_voting_allowed_for_configuration_no_unflag_perm(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        ballot_box.target_states[configuration].flagged = True
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "User does not have the permission to vote on flagged targets")

    def test_ballot_box_check_voting_allowed_for_configuration_unflag_perm_ok(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        force_voting_group(configuration, realm_user, can_unflag_target=True)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        ballot_box.target_states[configuration].flagged = True
        self.assertIsNone(ballot_box.check_voting_allowed_for_configuration(configuration, True))

    def test_ballot_box_check_voting_allowed_for_configuration_no_mark_malware_perm(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_voting_group(configuration, realm_user, can_unflag_target=True)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        ballot_box.target_states[configuration].state = TargetState.State.SUSPECT
        ballot_box.target_states[configuration].flagged = True
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "User does not have the permission to vote on malware targets")

    def test_ballot_box_check_voting_allowed_for_configuration_mark_malware_perm_ok(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        force_voting_group(configuration, realm_user, can_unflag_target=True, can_mark_malware=True)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        ballot_box.target_states[configuration].state = TargetState.State.SUSPECT
        ballot_box.target_states[configuration].flagged = True
        self.assertIsNone(ballot_box.check_voting_allowed_for_configuration(configuration, True))

    def test_ballot_box_check_voting_allowed_for_configuration_not_allowed_on_type(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "User is not allowed to vote on BINARY")

    def test_ballot_box_check_voting_allowed_for_configuration_banned_cert(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot_box.related_targets[Target.Type.CERTIFICATE][self.file_cert_sha256]["states"] = [
            {"pk": configuration.pk,
             "state": TargetState.State.BANNED,
             "flagged": True}  # BANNED cert
        ]
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, True),
                         "CERTIFICATE target is Banned")

    def test_ballot_box_check_voting_allowed_for_configuration_banned_cert_enough_perm(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        force_voting_group(configuration, realm_user, can_reset_target=True)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot_box.related_targets[Target.Type.CERTIFICATE][self.file_cert_sha256]["states"] = [
            {"pk": configuration.pk,
             "state": TargetState.State.BANNED,
             "flagged": True}  # BANNED cert
        ]
        self.assertIsNone(ballot_box.check_voting_allowed_for_configuration(configuration, True))

    def test_ballot_box_check_voting_allowed_for_configuration_downvote_bundle_error(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        self.assertEqual(ballot_box.check_voting_allowed_for_configuration(configuration, False),
                         "A BUNDLE cannot be downvoted")

    def test_ballot_box_get_default_votes(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        self.assertEqual(ballot_box._get_default_votes(True), {(configuration, True)})
        self.assertEqual(ballot_box._get_default_votes(False), set())

    def test_ballot_box_is_voting_allowed_no(self):
        realm, realm_user = force_realm_user()
        force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        ballot_box = BallotBox.for_realm_user(self.bundle_target, realm_user, all_configurations=True)
        self.assertFalse(ballot_box._is_voting_allowed(True))
        self.assertFalse(ballot_box._is_voting_allowed(False))

    def test_ballot_box_is_voting_allowed_no_existing_same(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        force_ballot(self.file_target, realm_user, ((configuration, True, 17),))
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        self.assertFalse(ballot_box._is_voting_allowed(True))

    def test_ballot_box_is_upvoting_downvoting_allowed(self):
        realm, realm_user = force_realm_user()
        force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        self.assertTrue(ballot_box.is_upvoting_allowed)
        self.assertTrue(ballot_box.is_downvoting_allowed)

    def test_ballot_box_cast_default_upvote(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=4,
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        votes = ballot_box.cast_default_votes(True, self.file_target)
        self.assertEqual(votes, {(configuration, True)})
        ts = ballot_box.target_states[configuration]
        ts.refresh_from_db()
        self.assertEqual(ts.state, TargetState.State.UNTRUSTED.value)
        self.assertFalse(ts.flagged)
        self.assertEqual(ts.score, 4)

    def test_ballot_box_get_configurations_allowed_votes(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        self.assertEqual(ballot_box.get_configurations_allowed_votes(), [(configuration, [True, False])])

    def test_ballot_box_cast_votes_anonymous_voter(self):
        ballot_box = BallotBox.for_realm_user(self.file_target, None)
        with self.assertRaises(VotingError) as cm:
            ballot_box.cast_votes([])
        self.assertEqual(cm.exception.args[0], "Anonymous voters cannot vote")

    def test_ballot_box_cast_votes_no_votes(self):
        _, realm_user = force_realm_user()
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user)
        with self.assertRaises(VotingError) as cm:
            ballot_box.cast_votes([])
        self.assertEqual(cm.exception.args[0], "No votes")

    def test_ballot_box_cast_votes_not_allowed(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BUNDLE])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        with self.assertRaises(VotingNotAllowedError) as cm:
            ballot_box.cast_votes([(configuration, True)])
        self.assertEqual(cm.exception.args[0], f"Voting upvote? True on configuration {configuration} is not allowed")

    def test_ballot_box_cast_votes(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=17,
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot_box.cast_votes([(configuration, False)])
        ts = ballot_box.target_states[configuration]
        ts.refresh_from_db()
        self.assertEqual(ts.state, TargetState.State.UNTRUSTED.value)
        self.assertTrue(ts.flagged)
        self.assertEqual(ts.score, -17)

    def test_ballot_box_create_or_update_ballot_duplicate_error(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        force_ballot(self.file_target, realm_user, ((configuration, True, 17),))
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        with self.assertRaises(DuplicateVoteError):
            ballot_box._create_or_update_ballot([(configuration, True)], self.file_target)

    def test_ballot_box_create_or_update_ballot_replace_existing(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm, default_ballot_target_types=[Target.Type.BINARY])
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot = ballot_box._create_or_update_ballot([(configuration, True)], self.file_target)
        self.assertIsNone(ballot.replaced_by)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        new_ballot = ballot_box._create_or_update_ballot([(configuration, False)], self.file_target)
        self.assertIsNone(new_ballot.replaced_by)
        ballot.refresh_from_db()
        self.assertEqual(ballot.replaced_by, new_ballot)
        self.assertEqual(new_ballot.realm_user, realm_user)
        self.assertEqual(new_ballot.target, self.file_target)

    def test_ballot_box_update_target_state_to_partially_allowlisted_to_globally_allowlisted(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=3,
            partially_allowlisted_threshold=5,
            globally_allowlisted_threshold=10,
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        # verify default state
        ts = ballot_box.target_states[configuration]
        self.assertEqual(ts.state, TargetState.State.UNTRUSTED)
        self.assertEqual(ts.score, 0)
        rule_qs = configuration.rule_set.filter(target=self.file_target)
        self.assertEqual(rule_qs.count(), 0)
        # first_vote
        ballot_box.cast_votes([(configuration, True)])
        # second vote
        _, realm_user2 = force_realm_user(realm=realm)
        ballot_box2 = BallotBox.for_realm_user(self.file_target, realm_user2, all_configurations=True)
        ts2 = ballot_box2.target_states[configuration]
        self.assertEqual(ts, ts2)
        self.assertEqual(ts2.state, TargetState.State.UNTRUSTED)
        self.assertEqual(ts2.score, 3)
        self.assertEqual(rule_qs.count(), 0)
        ballot_box2.cast_votes([(configuration, True)])
        # third vote
        _, realm_user3 = force_realm_user(realm=realm)
        ballot_box3 = BallotBox.for_realm_user(self.file_target, realm_user3, all_configurations=True)
        ts3 = ballot_box3.target_states[configuration]
        self.assertEqual(ts, ts3)
        self.assertEqual(ts3.state, TargetState.State.PARTIALLY_ALLOWLISTED)
        self.assertEqual(ts3.score, 6)
        self.assertEqual(rule_qs.count(), 1)
        rule = rule_qs.first()
        self.assertEqual(rule.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(set(rule.primary_users), {realm_user.username, realm_user2.username})
        ballot_box3.cast_votes([(configuration, True)])
        # fourth vote
        _, realm_user4 = force_realm_user(realm=realm)
        ballot_box4 = BallotBox.for_realm_user(self.file_target, realm_user4, all_configurations=True)
        ts4 = ballot_box4.target_states[configuration]
        self.assertEqual(ts4.state, TargetState.State.PARTIALLY_ALLOWLISTED)
        self.assertEqual(ts4.score, 9)
        self.assertEqual(rule_qs.count(), 1)
        rule2 = rule_qs.first()
        self.assertEqual(rule, rule2)
        self.assertEqual(rule2.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(set(rule2.primary_users), {realm_user.username, realm_user2.username, realm_user3.username})
        ballot_box4.cast_votes([(configuration, True)])
        ts4.refresh_from_db()
        self.assertEqual(ts4.state, TargetState.State.GLOBALLY_ALLOWLISTED)
        self.assertEqual(ts4.score, 12)
        self.assertEqual(rule_qs.count(), 1)
        rule3 = rule_qs.first()
        self.assertEqual(rule, rule3)
        self.assertEqual(rule3.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(len(rule3.primary_users), 0)

    def test_ballot_box_update_target_state_unflag(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=1,
        )
        force_voting_group(configuration, realm_user, can_unflag_target=True)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ts = ballot_box.target_states[configuration]
        ts.flagged = True  # simulate flagged target
        ts.save()
        ballot_box.cast_votes([(configuration, True)])
        ts.refresh_from_db()
        self.assertFalse(ts.flagged)
        self.assertEqual(ts.score, 1)

    def test_ballot_box_update_target_state_to_suspect_to_untrusted(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=1,
        )
        force_voting_group(
            configuration, realm_user,
            voting_weight=3,
            can_unflag_target=True,
            can_mark_malware=True,
        )
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot_box.cast_votes([(configuration, False)])
        ballot_box2 = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ts = ballot_box2.target_states[configuration]
        self.assertEqual(ts.state, TargetState.State.SUSPECT)
        self.assertEqual(ts.score, -3)
        self.assertTrue(ts.flagged)
        ballot_box2.cast_votes([(configuration, True)])
        ts.refresh_from_db()
        self.assertFalse(ts.flagged)
        self.assertEqual(ts.score, 3)
        self.assertEqual(ts.state, TargetState.State.UNTRUSTED)

    def test_ballot_box_update_target_state_to_banned(self):
        realm, realm_user = force_realm_user()
        configuration = force_configuration(
            voting_realm=realm,
            default_ballot_target_types=[Target.Type.BINARY],
            default_voting_weight=1,
            banned_threshold=-26,
        )
        force_voting_group(
            configuration, realm_user,
            voting_weight=50,
            can_unflag_target=True,
            can_mark_malware=True,
        )
        rule_qs = configuration.rule_set.filter(target=self.file_target)
        self.assertEqual(rule_qs.count(), 0)
        ballot_box = BallotBox.for_realm_user(self.file_target, realm_user, all_configurations=True)
        ballot_box.cast_votes([(configuration, False)])
        ts = ballot_box.target_states[configuration]
        ts.refresh_from_db()
        self.assertEqual(ts.state, TargetState.State.BANNED)
        self.assertEqual(ts.score, -50)
        self.assertTrue(ts.flagged)
        self.assertEqual(rule_qs.count(), 1)
        rule = rule_qs.first()
        self.assertEqual(rule.target, self.file_target)
        self.assertEqual(rule.policy, Rule.Policy.BLOCKLIST)

    def test_ballot_box_allowlist_bundle(self):
        configuration = force_configuration()
        rule_qs = configuration.rule_set.all()
        self.assertEqual(rule_qs.count(), 0)
        ballot_box = BallotBox.for_realm_user(self.bundle_target, None)
        ballot_box._globally_allowlist(configuration)
        self.assertEqual(rule_qs.count(), 1)
        rule = rule_qs.first()
        self.assertEqual(rule.target, self.file_target)
        self.assertEqual(rule.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(len(rule.primary_users), 0)

    def test_ballot_box_allowlist_metabundle(self):
        configuration = force_configuration()
        rule_qs = configuration.rule_set.all()
        self.assertEqual(rule_qs.count(), 0)
        ballot_box = BallotBox.for_realm_user(self.metabundle_target, None)
        ballot_box._globally_allowlist(configuration)
        self.assertEqual(rule_qs.count(), 1)
        rule = rule_qs.first()
        self.assertEqual(rule.target.type, Target.Type.SIGNING_ID)
        self.assertEqual(rule.target.identifier, self.file_signing_id)
        self.assertEqual(rule.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(len(rule.primary_users), 0)
