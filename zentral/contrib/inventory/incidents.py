import logging

from zentral.core.incidents import register_incident_class
from zentral.core.incidents.incidents import BaseIncident

from .models import Source


logger = logging.getLogger("zentral.contrib.inventory.incidents")


class InventorySourceStaleIncident(BaseIncident):
    incident_type = "inventory_source_stale"

    @classmethod
    def get_incident_key(cls, source_pk):
        # keyed on the SOURCE only — the machine comes from the event's serial number, which is what makes
        # this a MachineIncident. One incident per source, with a machine incident per affected machine.
        return {"inventory_source_pk": source_pk}

    def get_objects(self):
        try:
            pk = int(self.key["inventory_source_pk"])
        except (KeyError, ValueError, TypeError):
            logger.error("Wrong inventory source stale incident key %s", self.key)
            return []
        return list(Source.objects.filter(pk=pk))

    def get_objects_for_display(self):
        sources = self.get_objects()
        if sources:
            yield ("Inventory source", ("inventory.view_machinesnapshot",), sources)

    def get_name(self):
        try:
            source = self.get_objects()[0]
        except IndexError:
            return "Unknown inventory source stopped reporting"
        return f"{source.name} inventory stopped reporting"


register_incident_class(InventorySourceStaleIncident)
