from django.utils.crypto import get_random_string
from zentral.contrib.munki.compliance_checks import MunkiScriptCheck
from zentral.contrib.munki.models import ScriptCheck
from zentral.core.compliance_checks.models import ComplianceCheck


def force_script_check(
    type=ScriptCheck.Type.ZSH_STR,
    source="echo yolo",
    expected_result="yolo",
    tags=None,
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
    return sc
