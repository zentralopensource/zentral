import json
import logging
from collections import namedtuple

from django.db import connection, transaction

from zentral.core.events.base import EventMetadata
from zentral.core.incidents.models import IncidentUpdate, Severity
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


class BaseWatch:
    name = None            # registered slug: the `watch` column value and the metrics label
    interval = 300         # seconds between evaluations; the only pacing knob
    severities = {}        # reason -> Severity value. Leave empty for a watch that opens no incident.
    incident_class = None  # set it and core opens, escalates and closes the incident
    event_class = None     # the watch's own event type, covering every status

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
        # ONE transaction, and events posted on commit. The statements write state before iter_events()
        # runs: without this, a post that failed after the write would leave the row saying "already
        # fired" and the alert would be lost with nothing to notice it.
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
            if events:
                transaction.on_commit(lambda: [event.post() for event in events])
        logger.debug("Watch %s: %d changed, %d recovered, %d unwatched, %d event(s)",
                     self.name, len(changed), len(recovered), len(unwatched), len(events))
        return len(changed), len(recovered), len(events)
