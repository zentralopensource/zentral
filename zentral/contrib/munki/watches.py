import logging

from zentral.core.incidents.models import Severity
from zentral.core.watchers import register_watch
from zentral.core.watchers.watches import BaseWatch

from .events import MunkiAgentHealthEvent
from .incidents import MunkiAgentUnhealthyIncident


logger = logging.getLogger("zentral.contrib.munki.watches")


class MunkiAgentUnhealthyWatch(BaseWatch):
    """The munki agent on a machine is not completing runs.

    The CONTACT axis only. MunkiState carries a timestamp per phase of the agent's exchange, which is what
    lets one watch separate "gone" from "talking but never finishing" — the second looks perfectly healthy
    from outside, and is the population that runs munki and never posts back.

    Payload staleness — last_script_checks_run, last_managed_installs_sync, a stuck force_full_sync_at —
    is a DIFFERENT axis: those are independent of each other and can co-occur, so they are separate
    watches rather than more reasons here.
    """
    name = "munki_agent_unhealthy"
    interval = 900
    incident_class = MunkiAgentUnhealthyIncident
    event_class = MunkiAgentHealthEvent
    machine_scoped = True

    # Blunt, and in the days range: a threshold that must survive weekends, holidays and travel cannot be
    # derived from a reporting cadence. It filters for PERSISTENCE, which is what separates a wedged agent
    # from a closed laptop.
    period = 7 * 86400
    # …and a machine we have only just met is not reported at all. The preflight creates the row, so
    # without this every machine would read `never_completed` for the minutes between its first poll and
    # its first completed run. APNS does the same thing with min_target_age.
    min_age = 86400

    # ONE source of truth, most specific first. Both CASEs and the WHERE are generated from it, so the
    # rungs cannot drift apart — and because the WHERE is exactly the OR of these conditions, the CASE
    # always matches: no ELSE, and no chance of an ARRAY[NULL].
    ladder = (
        # never onboarded: the row exists (the preflight makes it) but no poll was ever recorded
        ("never_onboarded", "ms.last_preflight_at IS NULL", Severity.MINOR),
        # gone: stopped polling altogether
        ("gone", "ms.last_preflight_at < NOW() - interval '1 second' * %(period)s", Severity.MAJOR),
        # polling, but never once completed a run — invisible without the phase split
        ("never_completed", "ms.last_postflight_at IS NULL", Severity.MAJOR),
        # polling, and stopped completing runs: looks alive by every other signal
        ("stopped_completing",
         "ms.last_postflight_at < NOW() - interval '1 second' * %(period)s", Severity.MAJOR),
    )

    @property
    def severities(self):
        return {reason: severity.value for reason, _, severity in self.ladder}

    def _cases(self):
        reason_case = severity_case = ""
        for reason, condition, severity in self.ladder:
            reason_case += f"WHEN {condition} THEN '{reason}' "
            severity_case += f"WHEN {condition} THEN {severity.value} "
        return f"CASE {reason_case}END", f"CASE {severity_case}END"

    def _unhealthy(self):
        return " OR ".join(condition for _, condition, _ in self.ladder)

    @property
    def degraded_select(self):
        reason_case, severity_case = self._cases()
        return (
            f"SELECT %(watch)s, ms.id::text, ms.machine_serial_number, ARRAY[{reason_case}],"
            f"       ARRAY[]::varchar[], {severity_case},"
            "       jsonb_build_object('munki_msn', ms.machine_serial_number), NOW(), NOW() "
            "  FROM munki_munkistate AS ms"
            " WHERE ms.created_at < NOW() - interval '1 second' * %(min_age)s"
            f"   AND ({self._unhealthy()})"
        )

    # The cast goes on the ws side, never on ms.id: casting the indexed column forecloses the primary
    # key, and both of these become a scan of one row per machine instead of a lookup per degraded one.
    _MATCH_SUBJECT = "ms.id = ws.subject_id::integer"

    @property
    def still_degraded(self):
        return (
            "SELECT 1 FROM munki_munkistate AS ms"
            f" WHERE {self._MATCH_SUBJECT}"
            "   AND ms.created_at < NOW() - interval '1 second' * %(min_age)s"
            f"   AND ({self._unhealthy()})"
        )

    subject_alive = f"SELECT 1 FROM munki_munkistate AS ms WHERE {_MATCH_SUBJECT}"

    def get_query_kwargs(self):
        kwargs = super().get_query_kwargs()
        kwargs["period"] = self.period
        kwargs["min_age"] = self.min_age
        return kwargs

    # nothing else: the subject IS the machine, which rides on the metadata as the serial, and the
    # reasons are the whole story. Core builds the events.


register_watch(MunkiAgentUnhealthyWatch)
