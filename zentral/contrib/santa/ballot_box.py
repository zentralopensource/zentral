from datetime import datetime
import logging
from django.db import connection
from django.db.models import Q
from django.utils.functional import cached_property
from .models import Ballot, Configuration, EnrolledMachine, Rule, Target, TargetState, Vote, VotingGroup
from .utils import target_related_targets


logger = logging.getLogger("zentral.contrib.santa.ballot_box")


class BallotBoxError(Exception):
    pass


class ResetNotAllowedError(BallotBoxError):
    pass


class VotingError(BallotBoxError):
    pass


class VotingNotAllowedError(VotingError):
    pass


class DuplicateVoteError(VotingError):
    pass


class Voter:
    is_anonymous = False

    def __init__(self, realm_user, max_machine_age_days=90, all_configurations=False):
        self.realm_user = realm_user
        self.max_machine_age_days = max_machine_age_days
        self.all_configurations = all_configurations

    @cached_property
    def realm_groups(self):
        return [g for g, _ in self.realm_user.groups_with_types()]

    @cached_property
    def enrolled_machines(self):
        return EnrolledMachine.objects.current_for_primary_user(self.realm_user.username, self.max_machine_age_days)

    @cached_property
    def configurations(self):
        if self.all_configurations:
            # for the admin console
            configuration_iter = Configuration.objects.distinct().filter(
                # all configurations with the realm user's realm set as the voting realm
                Q(voting_realm=self.realm_user.realm)
                # or with a voting group based on one of the realm user's realm group
                | Q(votinggroup__realm_group__in=self.realm_groups)
            )
        else:
            # for the user portal
            # only the configuration of the active user machines
            configuration_iter = (
                em.enrollment.configuration
                for em, _ in self.enrolled_machines
                if em.enrollment.configuration.voting_realm == self.realm_user.realm
            )
        return sorted(set(configuration_iter), key=lambda c: c.name)

    @cached_property
    def voting_groups(self):
        return list(
            VotingGroup.objects.select_related("configuration")
                               .filter(realm_group__in=self.realm_groups,
                                       configuration__in=self.configurations)
        )

    def _iter_configuration_voting_groups(self, configuration):
        for voting_group in self.voting_groups:
            if voting_group.configuration == configuration:
                yield voting_group

    def _check_voting_group_perm(self, configuration, perm):
        return any(getattr(vg, perm) for vg in self._iter_configuration_voting_groups(configuration))

    def can_vote_on_target_type(self, configuration, target_type):
        if target_type in configuration.default_ballot_target_types:
            return True
        return any(
            target_type in vg.ballot_target_types
            for vg in self._iter_configuration_voting_groups(configuration)
        )

    def voting_weight(self, configuration):
        voting_weight = configuration.default_voting_weight
        for voting_group in self._iter_configuration_voting_groups(configuration):
            voting_weight = max(voting_weight, voting_group.voting_weight)
        return voting_weight

    def can_mark_malware(self, configuration):
        return self._check_voting_group_perm(configuration, "can_mark_malware")

    def can_unflag_target(self, configuration):
        return self._check_voting_group_perm(configuration, "can_unflag_target")

    def can_reset_target(self, configuration):
        return self._check_voting_group_perm(configuration, "can_reset_target")


class AnonymousVoter:
    is_anonymous = True

    def __init__(self):
        self.realm_user = None
        self.realm_groups = []
        self.voting_groups = []
        self.configurations = []
        self.enrolled_machines = []

    def can_vote_on_target_type(self, configuration, target_type):
        return False

    def voting_weight(self, configuration):
        return 0

    def can_mark_malware(self, configuration):
        return False

    def can_unflag_target(self, configuration):
        return False

    def can_reset_target(self, configuration):
        return False


class BallotBox:
    @classmethod
    def for_realm_user(cls, target, realm_user, lock_target=True, all_configurations=False):
        if realm_user:
            voter = Voter(realm_user, all_configurations=all_configurations)
        else:
            voter = AnonymousVoter()
        return cls(target, voter, lock_target=lock_target)

    def __init__(self, target, voter, lock_target=True):
        if lock_target:
            self.target = Target.objects.select_for_update().get(pk=target.pk)
        else:
            self.target = target
        self.voter = voter
        self._set_target_states()

    def _set_target_states(self):
        self.target_states = {}
        for configuration in self.voter.configurations:
            target_state, _ = TargetState.objects.get_or_create(
                target=self.target,
                configuration=configuration
            )
            self.target_states[configuration] = target_state

    @cached_property
    def related_targets(self):
        return target_related_targets(self.target)

    def _iter_related_target_states(self, configuration, target_types):
        for target_type in target_types:
            for target_info in self.related_targets.get(target_type, {}).values():
                for target_state in target_info["states"]:
                    if target_state["pk"] != configuration.pk:
                        continue
                    yield target_type, target_state

    def best_ballot_box(self, lock_target=True):
        if self.target.type == Target.Type.BUNDLE:
            preferred_target_types = [Target.Type.METABUNDLE, Target.Type.BUNDLE]
        else:
            preferred_target_types = [Target.Type.SIGNING_ID, Target.Type.CDHASH, Target.Type.BINARY]
        for target_type in preferred_target_types:
            if not any(
                self.voter.can_vote_on_target_type(configuration, target_type)
                for configuration in self.voter.configurations
            ):
                continue
            for target_info in self.related_targets.get(target_type, {}).values():
                target_identifier = target_info["identifier"]
                target = Target.objects.get(type=target_type, identifier=target_identifier)
                return BallotBox(target, self.voter, lock_target=lock_target)
        logger.error("No best ballot box found for target %s", self.target)

    def target_info(self):
        try:
            return self.related_targets[self.target.type][self.target.identifier]
        except KeyError:
            pass

    def publisher_info(self):
        publisher_info = {}
        for cert_target_info in self.related_targets.get(Target.Type.CERTIFICATE, {}).values():
            for cert_obj in cert_target_info["objects"]:
                team_id = cert_obj.get("ou")
                if team_id:
                    publisher_info["team_id"] = team_id
                publisher_name = cert_obj.get("o")
                if publisher_name:
                    publisher_info["name"] = publisher_name
                if len(publisher_info) == 2:
                    return publisher_info
        for team_id, team_id_target_info in self.related_targets.get(Target.Type.TEAM_ID, {}).items():
            publisher_info["team_id"] = team_id
            for team_id_obj in team_id_target_info["objects"]:
                publisher_name = team_id_obj.get("o")
                if publisher_name:
                    publisher_info["name"] = publisher_name
                    break
        return publisher_info

    @cached_property
    def existing_ballot(self):
        if self.voter.is_anonymous:
            return None
        # TODO decide what happens if we only have the user_uid
        try:
            return Ballot.objects.get(target=self.target, realm_user=self.voter.realm_user, replaced_by__isnull=True)
        except Ballot.DoesNotExist:
            pass

    @cached_property
    def existing_votes(self):
        votes = set()
        if not self.existing_ballot:
            return votes
        for vote in self.existing_ballot.vote_set.select_related("configuration").all():
            votes.add((vote.configuration, vote.was_yes_vote))
        return votes

    def check_voting_allowed_for_configuration(self, configuration, yes_vote):
        if self.voter.is_anonymous:
            return "Anonymous voter"
        try:
            target_state = self.target_states[configuration]
        except KeyError:
            return "No link to configuration"
        # cannot vote on banned targets
        if target_state.state == TargetState.State.BANNED:
            return "Target is banned"
        # cannot vote on globally allowlisted targets
        if target_state.state == TargetState.State.GLOBALLY_ALLOWLISTED:
            return "Target is globally allowlisted"
        # bundle information available?
        if self.target.type == Target.Type.BUNDLE and not self.target.bundle.uploaded_at:
            return "Missing bundle information"
        # contains a flagged targets?
        if self.target.type in (Target.Type.BUNDLE, Target.Type.METABUNDLE):
            for rel_target_type, rel_target_state in self._iter_related_target_states(
                configuration,
                (Target.Type.BINARY, Target.Type.CDHASH, Target.Type.SIGNING_ID)
            ):
                if rel_target_state["flagged"]:
                    return f"The target contains a flagged {rel_target_type} target"
        # flagged?
        if target_state.flagged and not self.voter.can_unflag_target(configuration):
            return "User does not have the permission to vote on flagged targets"
        # check perm if SUSPECT
        if target_state.state == TargetState.State.SUSPECT and not self.voter.can_mark_malware(configuration):
            return "User does not have the permission to vote on malware targets"
        # type allowed?
        if not self.voter.can_vote_on_target_type(configuration, self.target.type):
            return f"User is not allowed to vote on {self.target.type}"
        # check that the signing targets are not banned, if the user is not admin
        if self.target.type not in (Target.Type.CERTIFICATE, Target.Type.TEAM_ID):
            for rel_target_type, rel_target_state in self._iter_related_target_states(
                configuration,
                (Target.Type.CERTIFICATE, Target.Type.TEAM_ID)
            ):
                # TODO better perm?
                if (
                    rel_target_state["state"] == TargetState.State.BANNED
                    and not self.voter.can_reset_target(configuration)
                ):
                    return f"{rel_target_type} target is {TargetState.State.BANNED.label}"
        # cannot downvote a BUNDLE or METABUNDLE
        if self.target.type in (Target.Type.BUNDLE, Target.Type.METABUNDLE) and not yes_vote:
            return f"A {self.target.type} cannot be downvoted"

    def _get_default_votes(self, yes_vote):
        votes = set()
        for configuration in self.voter.configurations:
            if self.check_voting_allowed_for_configuration(configuration, yes_vote) is None:
                votes.add((configuration, yes_vote))
        return votes

    def _is_voting_allowed(self, yes_vote):
        votes = self._get_default_votes(yes_vote)
        if not votes:
            return False
        return votes != self.existing_votes

    @cached_property
    def is_upvoting_allowed(self):
        return self._is_voting_allowed(True)

    @cached_property
    def is_downvoting_allowed(self):
        return self._is_voting_allowed(False)

    def cast_default_votes(self, yes_vote, event_target):
        # for the user portal
        votes = self._get_default_votes(yes_vote)
        if votes:
            self._cast_verified_votes(votes, event_target)
        return votes

    def get_configurations_allowed_votes(self):
        # for the admin console
        allowed_votes = []
        for configuration in self.voter.configurations:
            cfg_allowed_votes = []
            for yes_vote in (True, False):
                if self.check_voting_allowed_for_configuration(configuration, yes_vote) is None:
                    cfg_allowed_votes.append(yes_vote)
            allowed_votes.append((configuration, cfg_allowed_votes))
        return allowed_votes

    def cast_votes(self, votes):
        # known voter?
        if self.voter.is_anonymous:
            raise VotingError("Anonymous voters cannot vote")
        # sanity check
        if not votes:
            raise VotingError("No votes")
        # check voting on each configuration
        for configuration, yes_vote in votes:
            if self.check_voting_allowed_for_configuration(configuration, yes_vote) is not None:
                raise VotingNotAllowedError(
                    f"Voting upvote? {yes_vote} on configuration {configuration} is not allowed"
                )
        self._cast_verified_votes(votes)

    def _cast_verified_votes(self, votes, event_target=None):
        self._create_or_update_ballot(votes, event_target)
        self._update_target_states(votes)

    def _create_or_update_ballot(self, votes, event_target):
        if not isinstance(votes, set):
            votes = set(votes)
        if votes == self.existing_votes:
            raise DuplicateVoteError
        ballot = Ballot.objects.create(
            target=self.target,
            event_target=event_target,
            realm_user=self.voter.realm_user,
            user_uid=self.voter.realm_user.username
        )
        if self.existing_ballot:
            self.existing_ballot.replaced_by = ballot
            self.existing_ballot.save()
        for configuration, yes_vote in votes:
            Vote.objects.create(
                ballot=ballot,
                configuration=configuration,
                was_yes_vote=yes_vote,
                weight=self.voter.voting_weight(configuration)
            )
        return ballot

    def _update_target_states(self, votes):
        for configuration, was_yes_vote in votes:
            with connection.cursor() as cursor:
                cursor.execute(
                    "select sum(v.weight * (case when v.was_yes_vote then 1 else -1 end)) "
                    "from santa_vote v "
                    "join santa_ballot b on (v.ballot_id = b.id) "
                    "left join santa_targetstate ts on (b.target_id = ts.target_id) "
                    "where b.target_id = %s and b.replaced_by_id is null "
                    "and (ts.reset_at is null or v.created_at > ts.reset_at) "
                    "and v.configuration_id = %s",
                    [self.target.pk, configuration.pk]
                )
                result = cursor.fetchone()
            new_score = result[0] or 0
            self._update_target_state(configuration, new_score, was_yes_vote)

    def _update_target_state(self, configuration, score, was_yes_vote):
        target_state = self.target_states[configuration]
        if was_yes_vote:
            if target_state.flagged and self.voter.can_unflag_target(configuration):
                target_state.flagged = False
            if target_state.state != TargetState.State.SUSPECT or self.voter.can_mark_malware(configuration):
                self._update_target_state_state(target_state, score)
        else:
            target_state.flagged = True
            self._update_target_state_state(target_state, score)
            if target_state.state != TargetState.State.BANNED and self.voter.can_mark_malware(configuration):
                target_state.state = TargetState.State.SUSPECT
        target_state.score = score
        target_state.save()

    def _update_target_state_state(self, target_state, score):
        configuration = target_state.configuration
        if score >= configuration.globally_allowlisted_threshold:
            self._globally_allowlist(configuration)
            if target_state.state != TargetState.State.GLOBALLY_ALLOWLISTED:
                target_state.state = TargetState.State.GLOBALLY_ALLOWLISTED
                return True
        elif score >= configuration.partially_allowlisted_threshold:
            self._partially_allowlist(configuration)
            if target_state.state != TargetState.State.PARTIALLY_ALLOWLISTED:
                target_state.state = TargetState.State.PARTIALLY_ALLOWLISTED
                return True
        elif score <= configuration.banned_threshold:
            self._blocklist(configuration)
            if target_state.state != TargetState.State.BANNED:
                target_state.state = TargetState.State.BANNED
                return True
        else:
            self._ensure_no_rules(configuration)
            if target_state.state != TargetState.State.UNTRUSTED:
                target_state.state = TargetState.State.UNTRUSTED
                return True
        return False

    def reset_target_state(self, configuration):
        if not self.voter.can_reset_target(configuration):
            raise ResetNotAllowedError
        target_state = self.target_states[configuration]
        target_state.score = 0
        target_state.flagged = False
        self._update_target_state_state(target_state, 0)
        target_state.reset_at = datetime.utcnow()
        target_state.save()

    # rules

    def _iter_rule_targets(self):
        if self.target.type == Target.Type.METABUNDLE:
            yield from self.target.metabundle.signing_id_targets.all()
        elif self.target.type == Target.Type.BUNDLE:
            yield from self.target.bundle.binary_targets.all()
        else:
            yield self.target

    def _update_or_create_rules(self, configuration, policy, primary_users=None):
        Rule.objects.bulk_create(
            [
                Rule(
                    configuration=configuration,
                    target=target,
                    policy=policy,
                    primary_users=primary_users if primary_users else [],
                    excluded_primary_users=[],
                ) for target in self._iter_rule_targets()
            ],
            update_conflicts=True,
            unique_fields=["configuration", "target"],
            update_fields=["policy", "primary_users", "excluded_primary_users"]
        )

    def _globally_allowlist(self, configuration):
        self._update_or_create_rules(configuration, Rule.Policy.ALLOWLIST)

    def _partially_allowlist(self, configuration):
        with connection.cursor() as cursor:
            cursor.execute(
                "select distinct coalesce(u.username, b.user_uid) "
                "from santa_ballot b "
                "left join realms_realmuser u on (b.realm_user_id = u.uuid) "
                "join santa_vote v on (b.id = v.ballot_id) "
                "join santa_targetstate ts on (b.target_id = ts.target_id) "
                "where b.target_id = %s "
                "and b.replaced_by_id is null "
                "and v.configuration_id = %s "
                "and v.was_yes_vote = 't' "
                "and (ts.reset_at is null or b.created_at > ts.reset_at)",
                [self.target.pk, configuration.pk]
            )
            primary_users = list(r[0] for r in cursor.fetchall() if r)
        self._update_or_create_rules(configuration, Rule.Policy.ALLOWLIST, primary_users)

    def _blocklist(self, configuration):
        self._update_or_create_rules(configuration, Rule.Policy.BLOCKLIST)

    def _ensure_no_rules(self, configuration):
        Rule.objects.filter(configuration=configuration, target__in=self._iter_rule_targets()).delete()
