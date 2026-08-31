import json
import logging
from collections import namedtuple

from django.db import connection, transaction

from zentral.core.events.base import EventMetadata
from zentral.core.incidents.models import IncidentUpdate, Severity, Status
from zentral.utils.time import naive_utcnow

from .events import SubjectUnwatchedEvent, WatchStatus


logger = logging.getLogger("zentral.core.watchers.watches")


# The two statements are owned by the framework, not by the watches. `previous_reasons` capture and the
# `IS DISTINCT FROM` guard are invariants of the protocol — a watch that got either wrong would either
# lose transitions or re-fire on every tick, so neither is left to a subclass.

DEGRADED_TEMPLATE = (
    "INSERT INTO watchers_watchstate"
    " (watch, subject_id, serial_number, reasons, previous_reasons, severity, incident_key,"
    "  first_fired_at, fired_at) "
    "{degraded_select} "
    "ON CONFLICT (watch, subject_id) DO UPDATE "
    "SET reasons = EXCLUDED.reasons,"
    # the bare table name is the PRE-update row: this is how both sides of the transition reach RETURNING
    "    previous_reasons = watchers_watchstate.reasons,"
    "    severity = EXCLUDED.severity,"
    # incident_key is deliberately NOT updated: like first_fired_at it belongs to the incident that was
    # opened, and re-deriving it later is what closing must never depend on
    "    fired_at = EXCLUDED.fired_at "
    "WHERE watchers_watchstate.reasons IS DISTINCT FROM EXCLUDED.reasons "
    "RETURNING watchers_watchstate.*"
)

DELETED_TEMPLATE = (
    "DELETE FROM watchers_watchstate AS ws "
    "WHERE ws.watch = %(watch)s AND NOT EXISTS ({still_degraded}) "
    # Both outcomes fall out of this one fact, so it is named for what it computes rather than for either
    # reading: still watched and no longer degraded is a RECOVERY, not still watched is UNWATCHED — the
    # subject left the watch's domain, deleted, archived or merely out of scope.
    "RETURNING ws.*, EXISTS ({subject_alive}) AS still_watched"
)


# The repair statements. Both read the incidents of the watch and emit what the incidents say is missing,
# and neither writes an incident: opening and closing stay on the events, where the pipeline applies them.
# The two apps are core, and the semantics needed here are already first class in the incidents one — an
# incident that is open, and a close that a human made after the fact.

UNREPORTED_TEMPLATE = (
    "SELECT ws.* FROM watchers_watchstate AS ws "
    "WHERE ws.watch = %(watch)s "
    # a row with no key cannot be matched against an incident, and re-emitting it every tick would never
    # converge. _incident_updates already logs that gap where it happens.
    "  AND ws.incident_key IS NOT NULL "
    # every transition moves fired_at, so this one window covers both the tick that wrote the row — whose
    # events are posted only after the commit — and the ticks after it, while the pipeline catches up.
    # Nothing else holds the repair back, so a grace of zero re-emits every transition one interval later.
    "  AND ws.fired_at < NOW() - interval '1 second' * %(reconcile_grace)s "
    "  AND NOT EXISTS ({reported})"
)

# `status_time > ws.fired_at` is the whole discriminator: a close that came AFTER this transition was
# somebody's decision, and a watch must not undo it. A close that came before it belongs to an earlier
# degradation, so this transition was never reported. open_values() covers IN_PROGRESS and REOPENED, which
# are reported too — an operator working an incident does not need it re-announced.
REPORTED_INCIDENT = (
    "SELECT 1 FROM incidents_incident AS i"
    " WHERE i.incident_type = %(incident_type)s AND i.key = ws.incident_key"
    "   AND (i.status = ANY(%(open_statuses)s) OR i.status_time > ws.fired_at)"
)

REPORTED_MACHINE_INCIDENT = (
    "SELECT 1 FROM incidents_incident AS i"
    " JOIN incidents_machineincident AS mi ON (mi.incident_id = i.id)"
    " WHERE i.incident_type = %(incident_type)s AND i.key = ws.incident_key"
    "   AND mi.serial_number = ws.serial_number"
    "   AND (mi.status = ANY(%(open_statuses)s) OR mi.status_time > ws.fired_at)"
)

# The other direction, and the one the sparse table cannot answer on its own: the row is deleted, so a lost
# close leaves an incident that no later tick will ever emit about again — the failure iter_unwatched_events
# exists to prevent, reintroduced by a publish that did not land.
#
# Only status = OPEN, and never the other open values: close_open_incident and close_open_machine_incident
# refuse to close anything else, so widening this would emit events that change nothing. The columns are the
# ones _metadata and _status_fields read; the state is gone, so reasons and subject_id cannot be recovered
# and are not invented.
_ORPHANED_COLUMNS = (
    "SELECT %(watch)s AS watch, NULL AS subject_id, {serial_number} AS serial_number,"
    "       ARRAY[]::varchar[] AS reasons, ARRAY[]::varchar[] AS previous_reasons,"
    "       i.key AS incident_key, {first_fired_at} AS first_fired_at "
)

ORPHANED_TEMPLATE = (
    _ORPHANED_COLUMNS.format(serial_number="NULL", first_fired_at="i.created_at") +
    "  FROM incidents_incident AS i"
    " WHERE i.incident_type = %(incident_type)s AND i.status = %(open_status)s"
    "   AND i.status_time < NOW() - interval '1 second' * %(reconcile_grace)s"
    "   AND NOT EXISTS (SELECT 1 FROM watchers_watchstate AS ws"
    "                    WHERE ws.watch = %(watch)s AND ws.incident_key = i.key)"
)

ORPHANED_MACHINE_TEMPLATE = (
    _ORPHANED_COLUMNS.format(serial_number="mi.serial_number", first_fired_at="mi.created_at") +
    "  FROM incidents_machineincident AS mi"
    "  JOIN incidents_incident AS i ON (i.id = mi.incident_id)"
    " WHERE i.incident_type = %(incident_type)s AND mi.status = %(open_status)s"
    "   AND mi.status_time < NOW() - interval '1 second' * %(reconcile_grace)s"
    # one event per orphaned machine incident and none for the parent: close_open_incident holds the parent
    # open while any machine incident is, and closes it with the last one
    "   AND NOT EXISTS (SELECT 1 FROM watchers_watchstate AS ws"
    "                    WHERE ws.watch = %(watch)s AND ws.incident_key = i.key"
    "                      AND ws.serial_number = mi.serial_number)"
)


WatchRunResult = namedtuple(
    "WatchRunResult", ["changed", "recovered", "unwatched", "reconciled", "closed", "events"]
)


class BaseWatch:
    name = None            # registered slug: the `watch` column value and the metrics label
    interval = 300         # seconds between evaluations; the only pacing knob
    severities = {}        # reason -> Severity value. Leave empty for a watch that opens no incident.
    incident_class = None  # set it and core opens, escalates and closes the incident
    event_class = None     # the watch's own event type, covering every status

    # Whether the subject IS a machine, which is what decides MachineIncident vs Incident. The
    # degraded_select already says it by writing a serial or NULL, but the repair statements start from the
    # incidents and have no row to read it off, so it is declared rather than inferred.
    machine_scoped = False

    # How long an unreported transition, or an unclosed incident, has to stand before the repair speaks.
    # It absorbs the pipeline: the events of this tick are posted after the commit, so everything is
    # briefly unreported, and a back-pressured pipeline makes brief mean minutes. None disables the repair.
    reconcile_grace = 900

    # supplied by the subclass — the predicates, and nothing else
    degraded_select = None    # SELECT producing the 9 insert columns, in order
    still_degraded = None     # correlated subquery: is ws.subject_id still degraded?
    subject_alive = None      # correlated subquery: is ws.subject_id still watched at all?

    def get_query_kwargs(self):
        "Parameters for both statements. Periods and thresholds ride in here, never string-formatted."
        return {"watch": self.name}

    def get_severity(self, reasons):
        if not self.severities:
            return None
        return max((self.severities[r] for r in reasons if r in self.severities), default=None)

    # what a watch adds to the events core builds for it

    def get_subjects(self, rows):
        """The subject behind each row, keyed by subject_id, in ONE query.

        Optional — a watch whose payload is the framework block alone needs nothing here. The lookup is
        the genuinely per-watch part: a different model, a different traversal, a different key.
        """
        return {}

    def get_payload(self, row, subject):
        """What this watch adds to the framework block. `subject` is None if the lookup missed.

        Optional. Never the status, the reasons or the timings — those are core's, so that they cannot
        take a different shape from one watch to the next.
        """
        return {}

    # the events themselves — all three statuses, built the same way

    def _metadata(self, row, status):
        # serial_number is NULL for a subject that is not a machine, and EventMetadata reads that as
        # "no machine", so the global-vs-machine-scoped distinction needs saying only in the SQL
        metadata = EventMetadata(machine_serial_number=row.serial_number)
        metadata.incident_updates = self._incident_updates(row, status)
        return metadata

    def _incident_updates(self, row, status):
        if self.incident_class is None:
            return []
        incident_key = self._incident_key(row)
        if not incident_key:
            # the watch opens incidents but its degraded_select never wrote a key, so this one can never
            # be closed. Say so on the first degradation rather than when something is finally archived.
            logger.error("Watch %s: no incident key on subject %s", self.name, row.subject_id)
            return []
        # the key comes from the ROW, never from the subject: it is matched as jsonb and a miss closes
        # nothing silently, so opening and closing must use one value, not two derivations of it
        severity = Severity(row.severity) if status is WatchStatus.DEGRADED else Severity.NONE
        return [IncidentUpdate(self.incident_class.incident_type, incident_key, severity)]

    @staticmethod
    def _status_fields(row, status, now):
        "The part of every watch event that belongs to the framework rather than to the watch."
        recovered = status is WatchStatus.RECOVERED
        return {"status": status.value,
                "watch": row.watch,
                "subject_id": row.subject_id,
                # a recovery is the empty array — the healthy state the sparse table never stores
                "reasons": [] if recovered else row.reasons,
                "previous_reasons": row.reasons if recovered else row.previous_reasons,
                # USE_TZ is False, so both sides are naive UTC
                "degraded_for": int((now - row.first_fired_at).total_seconds())}

    def iter_events(self, changed, recovered):
        """One event per row, in both directions. The statement detects; this emits.

        The default, not the only way: a watch whose emission is not one-per-row overrides this whole
        method — BenchmarkStalenessWatch emits only where `reasons` grew.
        """
        now = naive_utcnow()
        for rows, status in ((changed, WatchStatus.DEGRADED), (recovered, WatchStatus.RECOVERED)):
            subjects = self.get_subjects(rows)
            for row in rows:
                yield self.event_class(
                    self._metadata(row, status),
                    {**self._status_fields(row, status, now),
                     **self.get_payload(row, subjects.get(row.subject_id))},
                )

    def iter_unwatched_events(self, unwatched):
        """Close the incidents of subjects that stopped being watched while still degraded.

        An unwatched subject is NOT a recovery — nothing was fixed, it left the watch's domain — so this
        is separate from iter_events and a watch does not implement it. Core does, because the
        alternative is an incident nobody can ever close: the state row is deleted, so no later tick will
        emit about that subject again. The key comes from the row rather than the subject, which by now
        may not exist.
        """
        if self.incident_class is None:
            return
        now = naive_utcnow()
        for row in unwatched:
            # the framework block and nothing else: the subject may be gone, so there is no payload to
            # ask the watch for, and no object to link to that a reader could still open
            yield SubjectUnwatchedEvent(
                self._metadata(row, WatchStatus.UNWATCHED),
                self._status_fields(row, WatchStatus.UNWATCHED, now),
            )

    # the repair — the same emission, over the rows the incidents say were never reported

    def _reconcile(self, kwargs, deleted):
        """Transitions with no incident to show for them, and incidents with no transition left to close.

        Nothing to reconcile against without an incident class: an events-only watch leaves no record that
        an event was owed, so a lost one cannot be found. Its own table cannot answer the question either —
        the row says fired whether or not the post landed.
        """
        if self.incident_class is None or self.reconcile_grace is None:
            return [], []
        kwargs = dict(kwargs,
                      incident_type=self.incident_class.incident_type,
                      open_statuses=list(Status.open_values()),
                      open_status=Status.OPEN.value,
                      reconcile_grace=self.reconcile_grace)
        reported = REPORTED_MACHINE_INCIDENT if self.machine_scoped else REPORTED_INCIDENT
        unreported = self._fetch(UNREPORTED_TEMPLATE.format(reported=reported), kwargs)
        orphaned = self._fetch(
            ORPHANED_MACHINE_TEMPLATE if self.machine_scoped else ORPHANED_TEMPLATE, kwargs
        )
        # The rows deleted on this tick have a close event in flight, so their incidents still read open —
        # and status_time is the time the incident was OPENED, which the grace window does not reach. They
        # have to be excluded by identity. The forward direction needs no equivalent: fired_at moved with
        # the transition, so the window already covers it.
        just_closed = {self._close_key(row) for row in deleted}
        return unreported, [row for row in orphaned if self._close_key(row) not in just_closed]

    def _close_key(self, row):
        return json.dumps(self._incident_key(row), sort_keys=True), row.serial_number

    # execution

    @staticmethod
    def _incident_key(row):
        # a raw cursor bypasses JSONField.from_db_value, and the Django psycopg backend hands jsonb back
        # as the undecoded string so its own decoder can run — which it never does here
        key = row.incident_key
        if isinstance(key, str):
            key = json.loads(key)
        return key

    @staticmethod
    def _fetch(sql, kwargs):
        with connection.cursor() as cursor:
            cursor.execute(sql, kwargs)
            if cursor.description is None:
                return []
            row_class = namedtuple("WatchStateRow", [col.name for col in cursor.description])
            return [row_class(*row) for row in cursor.fetchall()]

    def run_once(self):
        kwargs = self.get_query_kwargs()
        # ONE transaction, with the events built from the RETURNING rows and posted on commit: posting them
        # inside would alert about transitions that a rollback then takes back. A publish that fails after
        # the commit therefore loses its event, and the row already says fired — which is what _reconcile
        # finds on a later tick, reading the incidents rather than this table. A watch that opens no
        # incident keeps the original at-most-once behaviour, because nothing records what it owed.
        with transaction.atomic():
            changed = self._fetch(
                DEGRADED_TEMPLATE.format(degraded_select=self.degraded_select), kwargs
            )
            deleted = self._fetch(
                DELETED_TEMPLATE.format(still_degraded=self.still_degraded,
                                        subject_alive=self.subject_alive),
                kwargs
            )
            recovered = [row for row in deleted if row.still_watched]
            unwatched = [row for row in deleted if not row.still_watched]
            events = list(self.iter_events(changed, recovered))
            events.extend(self.iter_unwatched_events(unwatched))
            # after the DELETE, never before it: a row recovering on this tick is already gone, so the
            # repair cannot announce it degraded and then recovered, and every row it does find has passed
            # still_degraded — there is no predicate left for it to re-check
            unreported, orphaned = self._reconcile(kwargs, deleted)
            events.extend(self.iter_events(unreported, []))
            events.extend(self.iter_unwatched_events(orphaned))
            if events:
                transaction.on_commit(lambda: [event.post() for event in events])
        logger.debug("Watch %s: %d changed, %d recovered, %d unwatched, %d event(s)",
                     self.name, len(changed), len(recovered), len(unwatched), len(events))
        if unreported or orphaned:
            # not debug: every one of these is an event that was owed and never arrived, so a rate that is
            # anything but zero is the interesting signal here, not the repair itself
            logger.warning("Watch %s: re-emitted %d transition(s), closed %d incident(s)",
                           self.name, len(unreported), len(orphaned))
        return WatchRunResult(len(changed), len(recovered), len(unwatched),
                              len(unreported), len(orphaned), len(events))
