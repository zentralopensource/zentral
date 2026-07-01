from functools import cached_property

from zentral.core.compliance_checks import register_compliance_check_class
from zentral.core.compliance_checks.compliance_checks import BaseComplianceCheck
from zentral.core.compliance_checks.models import ComplianceCheck

from .events import (TurboMSCPCheckComplianceCheckStatusUpdated,
                     TurboScriptComplianceCheckStatusUpdated)


def sync_script_compliance_check(script, on):
    "Create, update or delete the turbo script compliance check"
    created = updated = deleted = False
    if on:
        cc_defaults = {
            "model": TurboScript.get_model(),
            "name": script.name,
            "version": script.job.version,   # CC.version mirrors the Job's wire version
            "description": script.description,
        }
        if not script.compliance_check:
            script.compliance_check = ComplianceCheck.objects.create(**cc_defaults)
            script.save()
            created = True
        else:
            for key, val in cc_defaults.items():
                if getattr(script.compliance_check, key) != val:
                    setattr(script.compliance_check, key, val)
                    updated = True
            if updated:
                script.compliance_check.save()
    elif script.compliance_check:
        script.compliance_check.delete()
        # delete() only NULLs the FK column (SET_NULL); refresh the in-memory instance so the caller's
        # serialization (DRF response / audit event new_value) doesn't report the deleted check as still set
        script.compliance_check = None
        deleted = True
    return created, updated, deleted


def sync_mscp_check_compliance_check(mscp_check):
    "Mint or realign the mSCP check's compliance check (its name + version follow the identity / Job version)"
    # an mSCP check always has a compliance check (it IS one): minted from MSCPCheck.save() and realigned
    # after an edit. No delete / toggle, unlike the optional script check.
    name, version = mscp_check.compliance_check_name, mscp_check.job.version
    if not mscp_check.compliance_check_id:
        mscp_check.compliance_check = ComplianceCheck.objects.create(
            model=TurboMSCPCheck.get_model(), name=name, version=version)
        return True
    cc = mscp_check.compliance_check
    updated = cc.name != name or cc.version != version
    if updated:
        cc.name, cc.version = name, version
        cc.save()
    return updated


class TurboScript(BaseComplianceCheck):
    model_display = "Turbo script"
    required_view_permissions = ("turbo.view_script",)
    scoped_cc_query = (
        "select cc.model, cc.id, cc.name, cc.version "
        "from compliance_checks_compliancecheck as cc "
        "join turbo_script as s on (s.compliance_check_id = cc.id) "
        "join compliance_checks_machinestatus as ms on (ms.compliance_check_id = cc.id) "
        "where ms.serial_number = %(serial_number)s"
    )

    @cached_property
    def script(self):
        from .models import Script
        try:
            return self.compliance_check.turbo_script
        except Script.DoesNotExist:
            return None

    def get_redirect_url(self):
        return self.script.get_absolute_url()

    def build_status_updated_event(self, script, serial_number, status, status_time, previous_status):
        # the definition is passed in rather than read from self.script so the results hot path doesn't
        # pay a per-event query to dereference it
        return TurboScriptComplianceCheckStatusUpdated.build(
            script, serial_number, status, status_time, previous_status)


register_compliance_check_class(TurboScript)


class TurboMSCPCheck(BaseComplianceCheck):
    # named TurboMSCPCheck to avoid clashing with the turbo.MSCPCheck model; the stored discriminator is
    # the class name ("TurboMSCPCheck"), like every other compliance check class
    model_display = "mSCP check"
    required_view_permissions = ("turbo.view_mscpcheck",)
    scoped_cc_query = (
        "select cc.model, cc.id, cc.name, cc.version "
        "from compliance_checks_compliancecheck as cc "
        "join turbo_mscpcheck as mc on (mc.compliance_check_id = cc.id) "
        "join compliance_checks_machinestatus as ms on (ms.compliance_check_id = cc.id) "
        "where ms.serial_number = %(serial_number)s"
    )

    @cached_property
    def mscp_check(self):
        from .models import MSCPCheck
        try:
            return self.compliance_check.turbo_mscp_check
        except MSCPCheck.DoesNotExist:
            return None

    def get_redirect_url(self):
        return self.mscp_check.get_absolute_url()

    def build_status_updated_event(self, mscp_check, serial_number, status, status_time, previous_status):
        # the definition is passed in rather than read from self.mscp_check so the results hot path
        # doesn't pay a per-event query to dereference it
        return TurboMSCPCheckComplianceCheckStatusUpdated.build(
            mscp_check, serial_number, status, status_time, previous_status)


register_compliance_check_class(TurboMSCPCheck)
