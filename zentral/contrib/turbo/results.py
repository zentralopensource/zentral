import logging
from collections import namedtuple

from zentral.contrib.inventory.utils import add_machine_tags, remove_machine_tags
from zentral.core.compliance_checks.events import MachineComplianceChangeEvent
from zentral.core.compliance_checks.models import MachineStatus, Status
from zentral.core.compliance_checks.utils import update_machine_statuses
from .models import MachineJobStatus

logger = logging.getLogger("zentral.contrib.turbo.results")


# one parsed wire result: the resolved job/definition/job-status row plus the fields the batch needs.
# wire_ref is the raw entry echoed back as the TurboResultEvent payload. sort_key = (run time, batch index)
# so the latest run wins ties by batch order.
ParsedResult = namedtuple("ParsedResult", [
    "job", "definition", "machine_job_status", "kind", "version",
    "outcome", "exit_code", "ran_at", "sort_key", "wire_ref",
])


class ResultsBatch:
    """Accumulates one agent results POST and commits it: the per-machine job statuses, the compliance
    (cc) statuses (latest run wins per check, N/A dropped), the tag decisions and the machine-wide event."""

    def __init__(self, serial_number):
        self.serial_number = serial_number
        self.event_results = []      # wire refs, in receipt order
        self._job_statuses = {}      # mjs.pk -> MachineJobStatus, flushed once at commit
        self._cc_decisions = {}      # ComplianceCheck -> (sort_key, (status, status_time))
        self._cc_definitions = {}    # ComplianceCheck.pk -> definition (Script/MSCPCheck) for per-check events
        self._tag_decisions = {}     # Tag -> (sort_key, add)

    def add(self, parsed):
        self._record_job_status(parsed)
        # compliance + tagging only when the result matches the current definition version; the agent may
        # report a job several times in one batch (each is still an event), so the latest run wins for both
        if parsed.version == parsed.job.version:
            self._record_verdict(parsed)
            self._record_tag(parsed)
        self.event_results.append(parsed.wire_ref)

    @property
    def result_counts(self):
        # per-kind summary for the request event — how many results were posted, not their content
        counts = {}
        for ref in self.event_results:
            counts[ref["kind"]] = counts.get(ref["kind"], 0) + 1
        return counts

    def commit(self, request):
        self._apply_job_statuses()
        cc_statuses, cc_out_of_scope, max_cc_status_time = self._resolve_cc_statuses()
        # drop now-N/A checks before the machine-wide status is recomputed from what remains
        self._prune_cc_out_of_scope(cc_out_of_scope)
        self._apply_cc_statuses(cc_statuses, max_cc_status_time)
        self._apply_tags(request)

    # accumulation

    def _record_job_status(self, parsed):
        mjs = parsed.machine_job_status
        mjs.result_version = parsed.version
        # only a current-version run counts as a completed run: last_result_at is what closes a one-time
        # job (config gates on it), so a stale-version result records result_version but must not set it —
        # otherwise editing a one-time job's definition after an old run would close it before the new
        # version ever runs
        if parsed.version == parsed.job.version and parsed.ran_at:
            # a batch may carry runs out of chronological order (a drained backlog); keep the earliest as
            # first_result_at and the latest as last_result_at rather than whatever arrived last
            if mjs.first_result_at is None or parsed.ran_at < mjs.first_result_at:
                mjs.first_result_at = parsed.ran_at
            if mjs.last_result_at is None or parsed.ran_at > mjs.last_result_at:
                mjs.last_result_at = parsed.ran_at
        self._job_statuses[mjs.pk] = mjs

    def _record_verdict(self, parsed):
        status = self._verdict(parsed)
        if status is not None:
            cc = parsed.definition.compliance_check
            self._cc_definitions[cc.pk] = parsed.definition
            self._keep_latest(self._cc_decisions, cc, parsed.sort_key, (status, parsed.ran_at))

    def _record_tag(self, parsed):
        definition = parsed.definition
        # exit_code is None → couldn't run → leave the tag as-is
        if parsed.kind == "script" and definition.tag_id and parsed.exit_code is not None:
            self._keep_latest(self._tag_decisions, definition.tag, parsed.sort_key, parsed.exit_code == 0)

    @staticmethod
    def _keep_latest(store, key, sort_key, value):
        if key not in store or sort_key > store[key][0]:
            store[key] = (sort_key, value)

    @staticmethod
    def _verdict(parsed):
        # the compliance verdict for this result, or None when it carries no verdict
        if parsed.kind == "mscp_check":
            # the agent reports the mSCP verdict directly (the server can't interpret bundled mSCP logic);
            # the wire codes map straight to Status, minus PENDING ("no row") and unknown codes
            try:
                status = Status(parsed.outcome.get("status"))
            except ValueError:
                return None
            return None if status == Status.PENDING else status
        if parsed.kind == "script" and parsed.definition.compliance_check_id:
            # the agent reports the raw exit code: 0 = OK, > 0 = FAIL, couldn't run (None) = UNKNOWN
            if parsed.exit_code is None:
                return Status.UNKNOWN
            return Status.OK if parsed.exit_code == 0 else Status.FAILED
        return None

    # commit

    def _apply_job_statuses(self):
        if self._job_statuses:
            MachineJobStatus.objects.bulk_update(
                self._job_statuses.values(), ["result_version", "first_result_at", "last_result_at"])

    def _resolve_cc_statuses(self):
        # the latest verdict per check drives its stored status: N/A drops the row (event only), any other
        # status is recorded. A repeated check thus reaches update_machine_statuses at most once.
        cc_statuses = []
        cc_out_of_scope = set()
        max_cc_status_time = None
        for cc, (_, (status, status_time)) in self._cc_decisions.items():
            if status == Status.OUT_OF_SCOPE:
                cc_out_of_scope.add(cc)
            else:
                cc_statuses.append((cc, status, status_time))
                if status_time and (max_cc_status_time is None or status_time > max_cc_status_time):
                    max_cc_status_time = status_time
        return cc_statuses, cc_out_of_scope, max_cc_status_time

    def _prune_cc_out_of_scope(self, cc_out_of_scope):
        if cc_out_of_scope:
            MachineStatus.objects.filter(
                serial_number=self.serial_number, compliance_check__in=cc_out_of_scope).delete()

    def _apply_cc_statuses(self, cc_statuses, max_cc_status_time):
        status_time_by_pk = {cc.pk: status_time for cc, _, status_time in cc_statuses}
        for compliance_check_pk, status, previous_status in update_machine_statuses(self.serial_number, cc_statuses):
            if status == previous_status:
                continue
            if compliance_check_pk is None:
                # the machine-wide roll-up
                MachineComplianceChangeEvent.build_from_serial_number_and_statuses(
                    self.serial_number, status, max_cc_status_time, previous_status).post()
            else:
                # a single check flipped — the compliance check class knows which event to build
                # (script vs mSCP); mirror osquery / munki so probes can key on one check
                definition = self._cc_definitions[compliance_check_pk]
                status_time = status_time_by_pk.get(compliance_check_pk) or max_cc_status_time
                definition.compliance_check.loaded_compliance_check.build_status_updated_event(
                    definition, self.serial_number, status, status_time, previous_status).post()

    def _apply_tags(self, request):
        # apply the batch's tagging once, each tag following its latest run
        tags_to_add = {tag for tag, (_, add) in self._tag_decisions.items() if add}
        tags_to_remove = {tag for tag, (_, add) in self._tag_decisions.items() if not add}
        if tags_to_add:
            add_machine_tags(self.serial_number, tags_to_add, request)
        if tags_to_remove:
            remove_machine_tags(self.serial_number, tags_to_remove, request)
