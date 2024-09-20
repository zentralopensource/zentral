import uuid
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmGroup, RealmUser
from zentral.contrib.inventory.models import (EnrollmentSecret, File, MachineSnapshotCommit,
                                              MetaBusinessUnit, PrincipalUserSource)
from zentral.contrib.santa.events import (_commit_files, _create_bundle_binaries, _create_missing_bundles,
                                          _update_targets)
from zentral.contrib.santa.models import (Ballot, Configuration, EnrolledMachine, Enrollment,
                                          Rule, Target, TargetCounter,
                                          Vote, VotingGroup)
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


# rule


def force_rule(
    target_type=Target.Type.SIGNING_ID,
    target_identifier=None,
    target=None,
    configuration=None,
    policy=Rule.Policy.BLOCKLIST,
):
    if not target:
        target = force_target(target_type, target_identifier)
    if configuration is None:
        configuration = force_configuration()
    return Rule.objects.create(configuration=configuration, target=target, policy=policy)


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
    cls.file_target = Target.objects.get(type=Target.Type.BINARY, identifier=cls.file_sha256)
    cls.file = File.objects.get(sha_256=cls.file_sha256)
    cls.bundle_target = Target.objects.get(type=Target.Type.BUNDLE, identifier=cls.bundle_sha256)
    cls.bundle = cls.bundle_target.bundle
    cls.metabundle_target = cls.bundle.metabundle.target
    cls.metabundle_sha256 = cls.bundle.metabundle.target.identifier


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
