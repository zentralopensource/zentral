import logging

from django.core.exceptions import SuspiciousOperation

from zentral.contrib.inventory.events import post_machine_snapshot_raw_event
from zentral.utils.time import naive_utcnow
from .base import BaseEnrolledMachinePostView

logger = logging.getLogger("zentral.contrib.turbo.public_views.inventory")


class InventoryView(BaseEnrolledMachinePostView):
    """Ingest a full machine snapshot onto the inventory raw-event pipeline (inventory is not a job)."""

    request_type = "inventory"

    def do_post(self, ms_tree):
        if not isinstance(ms_tree, dict):
            raise SuspiciousOperation("Invalid machine snapshot")
        serial_number = self.serial_number
        ms_tree["source"] = {"module": "zentral.contrib.turbo", "name": "Turbo"}
        # the authenticated machine owns the snapshot — never trust a serial number from the body
        ms_tree["serial_number"] = serial_number
        ms_tree["reference"] = serial_number
        ms_tree["public_ip_address"] = self.ip
        # the agent normally reports last_seen in the snapshot; fall back to server time (and flag it) if not
        if not ms_tree.get("last_seen"):
            logger.warning("Turbo inventory from %s: no last_seen in snapshot, using server time", serial_number)
            ms_tree["last_seen"] = naive_utcnow()
        if self.business_unit:
            ms_tree["business_unit"] = self.business_unit.serialize()
        post_machine_snapshot_raw_event(ms_tree)
        return {}
