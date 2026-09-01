import logging

from zentral.core.incidents.models import Severity
from zentral.core.watchers import register_watch
from zentral.core.watchers.watches import BaseWatch

from .events import InventorySourceHealthEvent
from .incidents import InventorySourceStaleIncident


logger = logging.getLogger("zentral.contrib.inventory.watches")


class InventorySourceStaleWatch(BaseWatch):
    """One source stopped reporting for one machine.

    Per (machine, source), not per machine: a device can be perfectly alive with a single source broken,
    which is the more interesting failure and the one a machine-level watch would hide behind the
    machine's other live sources.
    """
    name = "inventory_source_stale"
    interval = 600
    # Deliberately blunt, and in the DAYS range. A threshold that must survive weekends, holidays, travel
    # and PTO cannot be derived from a reporting cadence — that heuristic false-positives every Monday.
    # Blunt is not a compromise here: it filters for PERSISTENCE, which is exactly what separates a broken
    # agent from a closed laptop.
    period = 7 * 86400
    severities = {"stale": Severity.MAJOR.value}
    incident_class = InventorySourceStaleIncident
    event_class = InventorySourceHealthEvent
    machine_scoped = True

    # The cast goes on the ws side, never on cms.id: casting the indexed column instead turns both of
    # these into a hash join over every current snapshot in the fleet, on every tick.
    _MATCH_SUBJECT = "cms.id = ws.subject_id::integer"

    degraded_select = (
        "SELECT %(watch)s, cms.id::text, cms.serial_number,"
        "       ARRAY['stale'], ARRAY[]::varchar[], %(severity)s,"
        # archiving a machine deletes the snapshot, taking the source pk with it, so the incident key is
        # captured here while the subject still exists
        "       jsonb_build_object('inventory_source_pk', cms.source_id), NOW(), NOW() "
        "  FROM inventory_currentmachinesnapshot AS cms"
        " WHERE cms.last_seen < NOW() - interval '1 second' * %(period)s"
    )
    still_degraded = (
        "SELECT 1 FROM inventory_currentmachinesnapshot AS cms"
        f" WHERE {_MATCH_SUBJECT}"
        "   AND cms.last_seen < NOW() - interval '1 second' * %(period)s"
    )
    subject_alive = (
        f"SELECT 1 FROM inventory_currentmachinesnapshot AS cms WHERE {_MATCH_SUBJECT}"
    )

    def get_query_kwargs(self):
        kwargs = super().get_query_kwargs()
        kwargs["period"] = self.period
        kwargs["severity"] = self.get_severity(["stale"])
        return kwargs

    @staticmethod
    def get_subjects(rows):
        """The source behind each row's snapshot, in one query.

        Still worth a method where the mdm equivalent is not: the rows carry snapshot pks and the payload
        wants the source, so there is a traversal here, not just a fetch.
        """
        from .models import CurrentMachineSnapshot
        subject_ids = {row.subject_id for row in rows}
        if not subject_ids:
            return {}
        return {
            str(cms.pk): cms.source.serialize_for_event()
            for cms in CurrentMachineSnapshot.objects.select_related("source").filter(
                pk__in=subject_ids
            )
        }

    def get_payload(self, row, subject):
        # subject is None when the snapshot went away between the statements and the lookup — the
        # transition still happened, and the incident update comes from the row, so the event still goes
        return {"source": subject, "period": self.period}


register_watch(InventorySourceStaleWatch)
