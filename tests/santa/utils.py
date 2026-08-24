import datetime
import json
import uuid

from django.test import Client
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmGroup, RealmUser

from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import (
    EnrollmentSecret,
    File,
    MachineSnapshotCommit,
    MetaBusinessUnit,
    PrincipalUserSource,
)
from zentral.contrib.santa.events import (
    _commit_files,
    _create_bundle_binaries,
    _create_missing_bundles,
    _update_targets,
)
from zentral.contrib.santa.models import (
    Ballot,
    Configuration,
    EnrolledMachine,
    Enrollment,
    Rule,
    Target,
    TargetCounter,
    TargetState,
    Vote,
    VotingGroup,
)
from zentral.contrib.santa.utils import update_metabundles

# realm


def force_realm(enabled_for_login=False, user_portal=False):
    return Realm.objects.create(
        name=get_random_string(12),
        enabled_for_login=enabled_for_login,
        user_portal=user_portal,
        backend="ldap",
        username_claim="username",
        email_claim="email",
    )


def force_realm_user(realm=None, username=None, email=None):
    username = username or get_random_string(12)
    email = email or username + "@zentral.com"
    realm = realm or force_realm()
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        email=email
    )
    return realm, realm_user


def force_realm_group(realm=None, parent=None):
    return RealmGroup.objects.create(
        realm=realm or force_realm(),
        display_name=get_random_string(12),
        parent=parent,
    )


def force_voting_group(
    configuration,
    realm_user,
    ballot_target_types=None,
    voting_weight=1,
    can_mark_malware=False,
    can_unflag_target=False,
    can_reset_target=False,
):
    realm_group = force_realm_group(realm=realm_user.realm)
    realm_user.groups.add(realm_group)
    if ballot_target_types is None:
        ballot_target_types = [Target.Type.METABUNDLE, Target.Type.SIGNING_ID]
    return VotingGroup.objects.create(
        configuration=configuration,
        realm_group=realm_group,
        ballot_target_types=ballot_target_types,
        voting_weight=voting_weight,
        can_mark_malware=can_mark_malware,
        can_unflag_target=can_unflag_target,
        can_reset_target=can_reset_target,
    )


# rule identifiers


def new_cdhash():
    return get_random_string(length=40, allowed_chars='abcdef0123456789')


def new_sha256():
    return get_random_string(length=64, allowed_chars='abcdef0123456789')


def new_team_id():
    return get_random_string(10, allowed_chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")


def new_signing_id_identifier():
    return ":".join((new_team_id(), get_random_string(10, allowed_chars="abcdefghij")))


# configuration


def force_configuration(
    lockdown=False,
    voting_realm=None,
    default_ballot_target_types=None,
    default_voting_weight=0,
    banned_threshold=-26,
    partially_allowlisted_threshold=5,
    globally_allowlisted_threshold=50,
):
    if lockdown:
        client_mode = Configuration.LOCKDOWN_MODE
    else:
        client_mode = Configuration.MONITOR_MODE
    if not default_ballot_target_types:
        default_ballot_target_types = []
    return Configuration.objects.create(
        name=get_random_string(12),
        client_mode=client_mode,
        voting_realm=voting_realm,
        default_ballot_target_types=default_ballot_target_types,
        default_voting_weight=default_voting_weight,
        banned_threshold=banned_threshold,
        partially_allowlisted_threshold=partially_allowlisted_threshold,
        globally_allowlisted_threshold=globally_allowlisted_threshold,
    )


# enrolled machine


def force_enrolled_machine(
    mbu=None, configuration=None,
    lockdown=False,
    santa_version="2024.5",
    primary_user=None,
    last_seen=None,
    last_sync_ok=None,
    last_postflight_at=None,
    forced_sync_type=None,
):
    if mbu is None:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
    if configuration is None:
        configuration = force_configuration()
    enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
    enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
    hardware_uuid = uuid.uuid4()
    serial_number = get_random_string(10)
    em = EnrolledMachine.objects.create(
        enrollment=enrollment,
        hardware_uuid=hardware_uuid,
        serial_number=serial_number,
        client_mode=Configuration.LOCKDOWN_MODE if lockdown else Configuration.MONITOR_MODE,
        santa_version=santa_version,
        primary_user=primary_user,
        last_sync_ok=last_sync_ok,
        last_postflight_at=last_postflight_at,
        forced_sync_type=forced_sync_type,
        forced_sync_type_at=(datetime.datetime(2026, 8, 20, 12, tzinfo=datetime.UTC)
                             if forced_sync_type else None),
    )
    if last_seen is not None:
        tree = {
            'source': {
                'module': 'zentral.contrib.santa',
                'name': 'Santa'
            },
            'reference': str(hardware_uuid),
            'serial_number': serial_number,
            'os_version': {'name': 'macOS', 'major': 14, 'minor': 6, 'patch': 1, 'build': '23G93'},
            'system_info': {'computer_name': 'godzilla'},
            'public_ip_address': '1.2.3.4',
            'last_seen': last_seen,
        }
        if primary_user:
            tree['principal_user'] = {
                'source': {'type': PrincipalUserSource.SANTA_MACHINE_OWNER},
                'unique_id': primary_user,
                'principal_name': primary_user,
            }
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree(tree)
    return em


# target


def force_target(type=Target.Type.SIGNING_ID, identifier=None):
    if identifier is None:
        if type == Target.Type.CDHASH:
            identifier = new_cdhash()
        if type == Target.Type.TEAM_ID:
            identifier = new_team_id()
        elif type == Target.Type.SIGNING_ID:
            identifier = new_signing_id_identifier()
        else:
            identifier = new_sha256()
    return Target.objects.create(type=type, identifier=identifier)


# target counter


def force_target_counter(target_type, blocked_count=0, collected_count=0, executed_count=0, is_rule=False):
    configuration = force_configuration()
    target = force_target(target_type)
    if is_rule:
        Rule.objects.create(
            configuration=configuration,
            target=target,
            policy=Rule.Policy.BLOCKLIST,
        )
    return TargetCounter.objects.create(
        configuration=configuration,
        target=target,
        blocked_count=blocked_count,
        collected_count=collected_count,
        executed_count=executed_count,
    )


# target state


def force_target_state(configuration=None, target=None, state=None, flagged=False):
    return TargetState.objects.create(
        configuration=configuration or force_configuration(),
        target=target or force_target(),
        state=state or TargetState.State.UNTRUSTED,
        flagged=flagged,
    )


# rule


def force_rule(
    target_type=Target.Type.SIGNING_ID,
    target_identifier=None,
    configuration=None,
    policy=Rule.Policy.BLOCKLIST,
    cel_expr="",
    description="",
    is_voting_rule=False,
    primary_users=None,
    serial_numbers=None,
    excluded_primary_users=None,
    excluded_serial_numbers=None,
):
    target = force_target(target_type, target_identifier)
    if configuration is None:
        configuration = force_configuration()
    return Rule.objects.create(
        configuration=configuration,
        target=target,
        policy=policy,
        cel_expr=cel_expr,
        description=description,
        is_voting_rule=is_voting_rule,
        primary_users=primary_users or [],
        serial_numbers=serial_numbers or [],
        excluded_primary_users=excluded_primary_users or [],
        excluded_serial_numbers=excluded_serial_numbers or [],
    )


# file


def add_file_to_test_class(cls):
    # file tree
    cls.cdhash = new_cdhash()
    cls.file_sha256 = new_sha256()
    cls.file_name = get_random_string(12)
    cls.file_bundle_name = get_random_string(12)
    cls.bundle_sha256 = new_sha256()
    cls.file_cert_sha256 = new_sha256()
    cls.file_team_id = new_team_id()
    cls.file_signing_id = f"{cls.file_team_id}:com.zentral.example"
    cls.file_cert_cn = f"Developer ID Application: YOLO ({cls.file_team_id})"
    event_d = {
        'current_sessions': [],
        'decision': 'ALLOW_UNKNOWN',
        'executing_user': 'root',
        'execution_time': 2242783327.585212,
        'file_bundle_id': 'servicecontroller:com.apple.stomp.transcoderx',
        'file_bundle_name': cls.file_bundle_name,
        'file_bundle_path': ('/Library/Frameworks/Compressor.framework/'
                             'Versions/A/Resources/CompressorTranscoderX.bundle'),
        'file_bundle_version': '3.5.3',
        'file_bundle_version_string': '3.5.3',
        'file_bundle_hash': cls.bundle_sha256,
        'file_bundle_binary_count': 1,
        'file_name': cls.file_name,
        'file_path': ('/Library/Frameworks/Compressor.framework/'
                      'Versions/A/Resources/CompressorTranscoderX.bundle/Contents/MacOS'),
        'cdhash': cls.cdhash,
        'file_sha256': cls.file_sha256,
        'signing_id': cls.file_signing_id,
        'team_id': cls.file_team_id,
        'logged_in_users': [],
        'parent_name': 'launchd',
        'pid': 95,
        'ppid': 1,
        'quarantine_timestamp': 0,
        'signing_chain': [{'cn': cls.file_cert_cn,
                           'ou': cls.file_team_id,
                           'org': 'Apple Inc.',
                           'sha256': cls.file_cert_sha256,
                           'valid_from': 1172268176,
                           'valid_until': 1421272976},
                          {'cn': 'Apple Code Signing Certification Authority',
                           'org': 'Apple Inc.',
                           'ou': 'Apple Certification Authority',
                           'sha256': '3afa0bf5027fd0532f436b39363a680aefd6baf7bf6a4f97f17be2937b84b150',
                           'valid_from': 1171487959,
                           'valid_until': 1423948759},
                          {'cn': 'Apple Root CA',
                           'org': 'Apple Inc.',
                           'ou': 'Apple Certification Authority',
                           'sha256': 'b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024',
                           'valid_from': 1146001236,
                           'valid_until': 2054670036}]
    }
    events = [event_d]
    targets = _update_targets(force_configuration(), events)
    _create_missing_bundles(events, targets)
    # shortcut, simulate a bundle binary upload
    events[0]["decision"] = "BUNDLE_BINARY"
    uploaded_bundles = _create_bundle_binaries(events)
    _commit_files(events)
    update_metabundles(uploaded_bundles)
    cls.cdhash_target = Target.objects.get(type=Target.Type.CDHASH, identifier=cls.cdhash)
    cls.file_target = Target.objects.get(type=Target.Type.BINARY, identifier=cls.file_sha256)
    cls.file = File.objects.get(sha_256=cls.file_sha256)
    cls.bundle_target = Target.objects.get(type=Target.Type.BUNDLE, identifier=cls.bundle_sha256)
    cls.bundle = cls.bundle_target.bundle
    cls.metabundle_target = cls.bundle.metabundle.target
    cls.metabundle_sha256 = cls.bundle.metabundle.target.identifier
    cls.cert_target = Target.objects.get(type=Target.Type.CERTIFICATE, identifier=cls.file_cert_sha256)
    cls.signing_id_target = Target.objects.get(type=Target.Type.SIGNING_ID, identifier=cls.file_signing_id)
    cls.team_id_target = Target.objects.get(type=Target.Type.TEAM_ID, identifier=cls.file_team_id)


# ballot


def force_ballot(
    target,
    realm_user,
    votes,
    replaced_by=None,
):
    ballot = Ballot.objects.create(
        target=target,
        realm_user=realm_user,
        user_uid=realm_user.username,
        replaced_by=replaced_by,
    )
    for configuration, yes_vote, weight in votes:
        Vote.objects.create(
            ballot=ballot,
            configuration=configuration,
            was_yes_vote=yes_vote,
            weight=weight
        )
    return ballot


# sync client


class SantaSyncClient:
    """Simulate the santa sync client rule database and sync stages.

    The rule database is only updated once the whole rule download is over, like
    the client does, so an interrupted sync leaves it untouched.
    """

    RULE_COUNT_TYPES = (
        (Target.Type.BINARY, "binary"),
        (Target.Type.CDHASH, "cdhash"),
        (Target.Type.CERTIFICATE, "certificate"),
        (Target.Type.SIGNING_ID, "signingid"),
        (Target.Type.TEAM_ID, "teamid"),
    )

    def __init__(self, enrolled_machine, santa_version=None):
        self.enrolled_machine = enrolled_machine
        self.secret = enrolled_machine.enrollment.secret.secret
        self.machine_id = str(enrolled_machine.hardware_uuid)
        self.serial_number = enrolled_machine.serial_number
        self.primary_user = enrolled_machine.primary_user
        # the reported version is what the preflight records and answers on, so it defaults to
        # the one of the machine the client drives
        self.santa_version = santa_version or enrolled_machine.santa_version
        self.client = Client()
        # rule database: (rule_type, identifier) -> policy
        self.rules = {}
        # rules created by the client itself, stored as binary rules
        self.transitive_rules = set()
        self.sync_type = None
        self.last_response = None

    # rule database

    def add_transitive_rule(self, identifier=None):
        identifier = identifier or new_sha256()
        self.transitive_rules.add(identifier)
        return identifier

    def rule_counts(self):
        counts = {f"{name}_rule_count": 0 for _, name in self.RULE_COUNT_TYPES}
        counts["compiler_rule_count"] = 0
        for (rule_type, _), policy in self.rules.items():
            for target_type, name in self.RULE_COUNT_TYPES:
                if rule_type == target_type:
                    counts[f"{name}_rule_count"] += 1
            if policy == "ALLOWLIST_COMPILER":
                counts["compiler_rule_count"] += 1
        # the client stores the transitive rules as binary rules
        counts["binary_rule_count"] += len(self.transitive_rules)
        counts["transitive_rule_count"] = len(self.transitive_rules)
        return counts

    def _apply_rules(self, rules):
        # santa returns before the cleanup when it did not receive any rule
        if not rules:
            return
        if self.sync_type == "CLEAN":
            self.rules = {}
        elif self.sync_type == "CLEAN_ALL":
            self.rules = {}
            self.transitive_rules = set()
        for rule in rules:
            key = (rule["rule_type"], rule["identifier"])
            if rule["policy"] == "REMOVE":
                self.rules.pop(key, None)
                self.transitive_rules.discard(rule["identifier"])
            else:
                self.rules[key] = rule["policy"]

    # sync stages

    def _post(self, url_name, data):
        url = reverse(f"santa_public:{url_name}", args=(self.machine_id,))
        response = self.client.post(
            url, json.dumps(data), content_type="application/json",
            headers={"Zentral-Authorization": f"Bearer {self.secret}"},
        )
        self.last_response = response
        return response

    def preflight(self, request_clean_sync=False, **extra):
        data = {
            "serial_number": self.serial_number,
            "machine_id": self.machine_id,
            "santa_version": self.santa_version,
            "hostname": "hostname",
            "os_build": "20C69",
            "os_version": "11.1",
            "client_mode": "MONITOR",
        }
        if self.primary_user:
            data["primary_user"] = self.primary_user
        if request_clean_sync:
            data["request_clean_sync"] = True
        # santa omits the rule counts set to 0
        data.update({k: v for k, v in self.rule_counts().items() if v})
        data.update(extra)
        response = self._post("preflight", data)
        if response.status_code == 200:
            json_response = response.json()
            self.sync_type = json_response.get("sync_type")
            if self.sync_type is None and json_response.get("clean_sync"):
                self.sync_type = "CLEAN"
        return response

    def rule_download(self, max_batches=None, between_batches=None):
        """Download the rules, and apply them unless the download was interrupted."""
        rules = []
        cursor = None
        batches = 0
        while True:
            data = {}
            if cursor:
                data["cursor"] = cursor
            response = self._post("ruledownload", data)
            if response.status_code != 200:
                return None
            json_response = response.json()
            rules.extend(json_response["rules"])
            cursor = json_response.get("cursor")
            batches += 1
            if max_batches is not None and batches >= max_batches:
                # interrupted download, nothing is written to the rule database
                return None
            if not cursor:
                break
            if between_batches:
                # something happens on the server between two batch requests
                between_batches(batches)
        self._apply_rules(rules)
        return rules

    def postflight(self, rules, rules_processed=None, **extra):
        data = {"machine_id": self.machine_id}
        data["syncType"] = self.sync_type or "NORMAL"
        if rules_processed is None:
            # santa drops the rules it could not convert and processes the others
            rules_processed = len(rules)
        # santa omits the counts set to 0
        for key, val in (("rules_received", len(rules)), ("rules_processed", rules_processed)):
            if val:
                data[key] = val
        data.update(extra)
        # santa omits the fields it does not set. syncType=None simulates a client older than
        # 2025.1, which does not report the sync type it performed
        return self._post("postflight", {k: v for k, v in data.items() if v is not None})

    def sync(self, request_clean_sync=False, max_batches=None, postflight=True, **extra):
        response = self.preflight(request_clean_sync=request_clean_sync, **extra)
        if response.status_code != 200:
            return response
        rules = self.rule_download(max_batches=max_batches)
        if rules is None:
            return self.last_response
        if postflight:
            return self.postflight(rules)
        return self.last_response


def assert_audit_event(test_case, post_event, action, instance, prev_value=None, call_index=0):
    """Check the audit event at call_index, and give its payload back for more assertions."""
    test_case.maxDiff = None
    event = post_event.call_args_list[call_index].args[0]
    test_case.assertIsInstance(event, AuditEvent)
    expected = {"action": action,
                "object": {"model": instance._meta.label_lower,
                           "pk": str(instance.pk)}}
    if action in ("created", "updated"):
        expected["object"]["new_value"] = instance.serialize_for_event()
    if prev_value is not None:
        expected["object"]["prev_value"] = prev_value
    test_case.assertEqual(event.payload, expected)
    metadata = event.metadata.serialize()
    test_case.assertEqual(sorted(metadata["tags"]), ["santa", "zentral"])
    return event.payload, metadata


def assert_no_enrollment_secret(test_case, payload, enrollment):
    """EnrollmentSecret.serialize_for_event() leaves the secret out on purpose.

    The secret is the credential that enrolls a machine, so a regression there puts a live
    credential in every event store.
    """
    test_case.assertNotIn(enrollment.secret.secret, json.dumps(payload))
