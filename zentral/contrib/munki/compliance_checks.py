from datetime import datetime
import logging
from django.db import transaction
from django.utils.functional import cached_property
from zentral.core.compliance_checks import register_compliance_check_class
from zentral.core.compliance_checks.compliance_checks import BaseComplianceCheck
from zentral.core.compliance_checks.events import MachineComplianceChangeEvent
from zentral.core.compliance_checks.models import MachineStatus, Status
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
    events = []
    for compliance_check_pk, status, previous_status in status_updates:
        if status == previous_status:
            # status not updated, no event
            continue
        if compliance_check_pk:
            script_check = cc_d[compliance_check_pk]
            events.append(MunkiScriptCheckStatusUpdated.build_update(
                script_check,
                serial_number, status, status_time, previous_status
            ))
        else:
            events.append(MachineComplianceChangeEvent.build_from_serial_number_and_statuses(
                serial_number, status, status_time, previous_status
            ))

    if events:

        def post_events():
            for event in events:
                event.post()

        transaction.on_commit(lambda: post_events())


def prune_out_of_scope_machine_statuses(serial_number, in_scope_cc_ids):
    events = []
    for machine_status in (MachineStatus.objects.select_related("compliance_check__script_check")
                                                .filter(serial_number=serial_number,
                                                        compliance_check__script_check__isnull=False)
                                                .exclude(compliance_check__pk__in=in_scope_cc_ids)):
        events.append(MunkiScriptCheckStatusUpdated.build_update(
            machine_status.compliance_check.script_check,
            serial_number,
            Status.OUT_OF_SCOPE, datetime.utcnow(),
            Status(machine_status.status)
        ))
        machine_status.delete()
    if events:

        def post_events():
            for event in events:
                event.post()

        transaction.on_commit(lambda: post_events())
