import uuid
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.santa.models import Configuration, EnrolledMachine, Enrollment, Rule, Target, TargetCounter


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


def force_configuration(lockdown=False):
    if lockdown:
        client_mode = Configuration.LOCKDOWN_MODE
    else:
        client_mode = Configuration.MONITOR_MODE
    return Configuration.objects.create(name=get_random_string(12), client_mode=client_mode)


# enrolled machine


def force_enrolled_machine(
    mbu=None, configuration=None,
    lockdown=False,
    santa_version="2024.5",
):
    if mbu is None:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
    if configuration is None:
        configuration = force_configuration()
    enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
    enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
    return EnrolledMachine.objects.create(
        enrollment=enrollment,
        hardware_uuid=uuid.uuid4(),
        serial_number=get_random_string(10),
        client_mode=Configuration.LOCKDOWN_MODE if lockdown else Configuration.MONITOR_MODE,
        santa_version=santa_version,
    )


# target


def force_target(type=Target.SIGNING_ID, identifier=None):
    if identifier is None:
        if type == Target.CDHASH:
            identifier = new_cdhash()
        if type == Target.TEAM_ID:
            identifier = new_team_id()
        elif type == Target.SIGNING_ID:
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
            policy=Rule.BLOCKLIST,
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
    target_type=Target.SIGNING_ID,
    target_identifier=None,
    configuration=None,
    policy=Rule.BLOCKLIST,
):
    target = force_target(target_type, target_identifier)
    if configuration is None:
        configuration = force_configuration()
    return Rule.objects.create(configuration=configuration, target=target, policy=policy)
