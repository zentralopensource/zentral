import hashlib
import logging
from .utils import get_blueprint_declaration_identifier


__all__ = ["build_target_management_status_subscriptions"]


logger = logging.getLogger("zentral.contrib.mdm.declarations.management")


# https://developer.apple.com/documentation/devicemanagement/managementstatussubscriptions
# https://developer.apple.com/documentation/devicemanagement/status_reports
def build_target_management_status_subscriptions(target):
    status_items = []
    if target.client_capabilities:
        try:
            supported_status_items = target.client_capabilities["supported-payloads"]["status-items"]
        except KeyError:
            logger.warning("Target %s: could not find supported status items", target)
        else:
            status_items = [si for si in supported_status_items if not si.startswith("test.")]
    if not status_items:
        # default status items supported by all clients
        status_items = [
            "device.identifier.serial-number",
            "device.identifier.udid",
            "device.model.family",
            "device.model.identifier",
            "device.model.marketing-name",
            "device.operating-system.build-version",
            "device.operating-system.family",
            "device.operating-system.marketing-name",
            "device.operating-system.version",
            "management.client-capabilities",
            "management.declarations",
        ]
    status_items.sort()
    payload = {"StatusItems": []}
    h = hashlib.sha1()
    for status_item in sorted(status_items):
        h.update(status_item.encode("utf-8"))
        payload["StatusItems"].append({"Name": status_item})
    return {
        "Identifier": get_blueprint_declaration_identifier(target.blueprint, "management-status-subscriptions"),
        "Payload": payload,
        "ServerToken": h.hexdigest(),
        "Type": "com.apple.configuration.management.status-subscriptions"
    }
