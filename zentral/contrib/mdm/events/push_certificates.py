import logging

from zentral.core.events import register_event_type
from zentral.core.events.base import BaseEvent


logger = logging.getLogger("zentral.contrib.mdm.events.push_certificates")


# emitted by PushCertificateExpiryWatch, not by any request path


class PushCertificateHealthEvent(BaseEvent):
    """One event type for the whole expiry lifecycle — `status` says whether it got worse or was renewed.

    Not one type per outcome: an alert and its resolution belong on the same stream, or whoever routed
    the alert has to remember to route the all-clear too, and a page that never closes is the failure
    nobody notices until 3am.
    """
    event_type = "mdm_push_certificate_health"
    tags = ["mdm", "push_certificate_health", "watch"]

    def get_linked_objects_keys(self):
        keys = {}
        pk = (self.payload.get("push_certificate") or {}).get("pk")
        if pk:
            keys["mdm_push_certificate"] = [(pk,)]
        return keys


register_event_type(PushCertificateHealthEvent)
