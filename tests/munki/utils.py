from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.munki.compliance_checks import MunkiScriptCheck
from zentral.contrib.munki.models import Configuration, Enrollment, EnrolledMachine, MunkiState, ScriptCheck
from zentral.core.compliance_checks.models import ComplianceCheck


def force_configuration(
    auto_reinstall_incidents=False,
    auto_failed_install_incidents=False,
):
    return Configuration.objects.create(
        name=get_random_string(12),
        auto_failed_install_incidents=auto_failed_install_incidents,
        auto_reinstall_incidents=auto_reinstall_incidents,
    )


def force_enrollment(
    configuration=None,
    enrollment_secret=None,
    meta_business_unit=None,
    tags=None,
):
    if configuration is None:
        configuration = force_configuration()
    if enrollment_secret is None:
        if meta_business_unit is None:
            meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=meta_business_unit)
    if tags:
        enrollment_secret.tags.set(tags)
    return Enrollment.objects.create(
        configuration=configuration,
        secret=enrollment_secret
    )


def force_script_check(
    type=ScriptCheck.Type.ZSH_STR,
    source="echo yolo",
    expected_result="yolo",
    tags=None,
    excluded_tags=None,
    arch_arm64=True,
    arch_amd64=True,
    min_os_version="",
    max_os_version="",
):
    cc = ComplianceCheck.objects.create(
        name=get_random_string(12),
        model=MunkiScriptCheck.get_model(),
    )
    sc = ScriptCheck.objects.create(
        compliance_check=cc,
        type=type,
        source=source,
        expected_result=expected_result,
        arch_amd64=arch_amd64,
        arch_arm64=arch_arm64,
        min_os_version=min_os_version,
        max_os_version=max_os_version,
    )
    if tags is not None:
        sc.tags.set(tags)
    if excluded_tags is not None:
        sc.excluded_tags.set(excluded_tags)
    return sc


def make_enrolled_machine(enrollment, tag_name=None):
    em = EnrolledMachine.objects.create(enrollment=enrollment,
                                        serial_number=get_random_string(32),
                                        token=get_random_string(64))
    if tag_name:
        tag = Tag.objects.create(name=tag_name)
        MachineTag.objects.create(serial_number=em.serial_number, tag=tag)
    return em


def force_munki_state(serial_number=None):
    return MunkiState.objects.create(
        machine_serial_number=serial_number or get_random_string(12),
        munki_version="6.5.1",
        user_agent="Zentral/munkipostflight 0.14",
    )
