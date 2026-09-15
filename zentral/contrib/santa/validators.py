from typing import Any

from .models import Configuration, ScopedClientMode, voting_portal_event_detail_url


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


class ScopedClientModeValidator:

    # the configuration is not a form field, so that an entry cannot be reparented
    def __init__(self, configuration, data: dict[str, Any], pk=None):
        self.configuration = configuration
        self.data = data
        self.pk = pk
        self.errors = {}

    def validate(self):
        # the configuration is excluded from the form, and Django drops every unique check that
        # names an excluded field, so (configuration, name) is only enforced by the constraint
        name = self.data.get("name")
        if name:
            qs = self.configuration.scopedclientmode_set.filter(name=name)
            if self.pk:
                qs = qs.exclude(pk=self.pk)
            if qs.exists():
                self.errors.update({"name": "A scoped client mode with this name already exists"})

        event_detail_source = self.data.get("event_detail_source")
        if event_detail_source == ScopedClientMode.EventDetailSource.VOTING_PORTAL:
            if not voting_portal_event_detail_url(self.configuration.voting_realm):
                self.errors.update(
                    {"event_detail_source": "The configuration has no voting realm with the user portal enabled"}
                )
        elif event_detail_source == ScopedClientMode.EventDetailSource.CUSTOM:
            if not self.data.get("event_detail_url"):
                self.errors.update({"event_detail_url": "This field is required"})

        for attr in ("serial_numbers", "primary_users", "tags"):
            excluded_attr = f"excluded_{attr}"
            included = self.data.get(attr) or []
            excluded = self.data.get(excluded_attr) or []
            conflicts = sorted(str(i) for i in included if i in excluded)
            if conflicts:
                self.errors.update(
                    {excluded_attr: "Both included and excluded: " + ", ".join(conflicts)}
                )

        return self.errors
