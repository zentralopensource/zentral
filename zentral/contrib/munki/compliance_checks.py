import logging
from django.utils.functional import cached_property
from zentral.core.compliance_checks import register_compliance_check_class
from zentral.core.compliance_checks.compliance_checks import BaseComplianceCheck
from zentral.core.compliance_checks.models import Status
from zentral.core.compliance_checks.utils import update_machine_statuses
from .events import MunkiScriptCheckStatusUpdated
from .models import ScriptCheck


logger = logging.getLogger("zentral.contrib.osquery.compliance_checks")


def convert_bool_expected_result(expected_result):
    expected_result = expected_result.lower()
    if expected_result in ("f", "false"):
        expected_result = "0"
    elif expected_result in ("t", "true"):
        expected_result = "1"
    expected_result = int(expected_result)
    assert expected_result in (0, 1)
    return bool(expected_result)


def validate_expected_result(script_check_type, expected_result):
    if script_check_type == ScriptCheck.Type.ZSH_INT:
        try:
            int(expected_result)
        except ValueError:
            return False, "Invalid integer"
    elif script_check_type == ScriptCheck.Type.ZSH_BOOL:
        try:
            convert_bool_expected_result(expected_result)
        except (AssertionError, ValueError):
            return False, "Invalid boolean"
    return True, None


def serialize_script_check_for_job(script_check):
    d = {
        "pk": script_check.pk,
        "version": script_check.compliance_check.version,
        "type": str(script_check.type),
        "source": script_check.source,
    }
    if script_check.type == ScriptCheck.Type.ZSH_INT:
        d["expected_result"] = int(script_check.expected_result)
    elif script_check.type == ScriptCheck.Type.ZSH_BOOL:
        d["expected_result"] = convert_bool_expected_result(script_check.expected_result)
    else:
        d["expected_result"] = script_check.expected_result
    return d


class MunkiScriptCheck(BaseComplianceCheck):
    model_display = "Script check"
    required_view_permissions = ("munki.view_scriptcheck",)
    scoped_cc_query = (
        "select cc.model, cc.id, cc.name, cc.version "
        "from compliance_checks_compliancecheck as cc "
        "join munki_scriptcheck as sc on (sc.compliance_check_id = cc.id) "
        "join compliance_checks_machinestatus as ms on (ms.compliance_check_id = cc.id) "
        "where ms.serial_number = %(serial_number)s"
    )

    @cached_property
    def script_check(self):
        try:
            return self.compliance_check.script_check
        except ScriptCheck.DoesNotExist:
            return

    def get_redirect_url(self):
        return self.script_check.get_absolute_url()


register_compliance_check_class(MunkiScriptCheck)


def update_machine_munki_script_check_statuses(serial_number, results, status_time):
    sc_d = {
        sc.pk: sc for sc in
        ScriptCheck.objects.select_related("compliance_check").filter(pk__in=[r["pk"] for r in results])
    }
    compliance_check_statuses = []
    cc_d = {}
    for result in results:
        script_check_pk = result["pk"]
        try:
            script_check = sc_d[script_check_pk]
        except KeyError:
            logger.error("Machine %s: unknown script check %s in result",
                         serial_number, script_check_pk)
            continue
        try:
            status = Status(result["status"])
        except ValueError:
            logger.error("Machine %s: unknown status value for script check %s in result",
                         serial_number, script_check_pk)
            continue
        if script_check.compliance_check.version != result["version"]:
            logger.info("Machine %s: result for outdated script check %s",
                        serial_number, script_check_pk)
            # outdated status
            continue
        cc_d[script_check.compliance_check.pk] = script_check
        compliance_check_statuses.append((script_check.compliance_check, status, status_time))
    status_updates = update_machine_statuses(serial_number, compliance_check_statuses)
    for compliance_check_pk, status_value, previous_status_value in status_updates:
        if status_value == previous_status_value:
            # status not updated, no event
            continue
        script_check = cc_d[compliance_check_pk]
        event = MunkiScriptCheckStatusUpdated.build_update(
            script_check,
            serial_number,
            Status(status_value), status_time,
            Status(previous_status_value) if previous_status_value is not None else None
        )
        event.post()
