from typing import Any

from .models import Configuration, voting_portal_event_detail_url


class ConfigurationValidator:

    def __init__(self, data: dict[str, Any]):
        self.data = data
        self.errors = {}

    def validate(self):
        # event detail
        event_detail_source = self.data.get("event_detail_source")
        if event_detail_source == Configuration.EventDetailSource.VOTING_PORTAL:
            if not voting_portal_event_detail_url(self.data.get("voting_realm")):
                self.errors.update(
                    {"event_detail_source": "Requires a voting realm with the user portal enabled"}
                )
        elif event_detail_source == Configuration.EventDetailSource.CUSTOM:
            if not self.data.get("event_detail_url"):
                self.errors.update({"event_detail_url": "This field is required"})

        return self.errors
