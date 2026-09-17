import re
from typing import Any

from .models import Configuration, ScopedClientMode, voting_portal_event_detail_url


# Python accepts an inline flag group only at the start of a pattern, and every pattern is
# wrapped when the policies are composed. ICU accepts it in both positions, so re.compile()
# cannot be the one that reports this.
INLINE_FLAGS_RE = re.compile(r"\(\?[aiLmsux]+\)")


def validate_path_regex(regex):
    """The error a path pattern gets, or None. The patterns of one policy are composed into one
    alternation, so a pattern has to be safe to wrap as well as valid."""
    if INLINE_FLAGS_RE.search(regex):
        return "Scoped inline flags are required, for example (?i:abc)"
    try:
        compiled = re.compile(regex)
    except re.error as e:
        return f"Invalid regex: {e}"
    if compiled.groups:
        return "Capture groups are not allowed, use a non capturing group: (?:abc)"
    if compiled.match("") is not None:
        # a part that matches an empty path matches at position 0, so it opens the whole
        # composed pattern to every path
        return "This pattern matches an empty path, so it matches every path. Use .+ and not .*"
    return None


class ConfigurationValidator:

    def __init__(self, data: dict[str, Any], instance=None):
        self.data = data
        self.instance = instance
        self.errors = {}

    def validate(self):
        # path regexes. Only a pattern that changed is validated: a pattern stored before the
        # composition may be valid ICU and not valid here, and it must not block an edit of
        # another field. The composition falls back to it, so it keeps being enforced.
        for attr in ("allowed_path_regex", "blocked_path_regex"):
            regex = self.data.get(attr)
            if not regex or (self.instance is not None and getattr(self.instance, attr) == regex):
                continue
            error = validate_path_regex(regex)
            if error:
                self.errors.update({attr: error})

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


class ScopedConfigurationItemValidator:

    def __init__(self, configuration, data: dict[str, Any]):
        self.configuration = configuration
        self.data = data
        self.errors = {}

    def validate(self):
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


class ScopedClientModeValidator(ScopedConfigurationItemValidator):

    def validate(self):
        super().validate()

        event_detail_source = self.data.get("event_detail_source")
        if event_detail_source == ScopedClientMode.EventDetailSource.VOTING_PORTAL:
            if not voting_portal_event_detail_url(self.configuration.voting_realm):
                self.errors.update(
                    {"event_detail_source": "The configuration has no voting realm with the user portal enabled"}
                )
        elif event_detail_source == ScopedClientMode.EventDetailSource.CUSTOM:
            if not self.data.get("event_detail_url"):
                self.errors.update({"event_detail_url": "This field is required"})

        return self.errors


class ScopedPathRegexValidator(ScopedConfigurationItemValidator):

    def validate(self):
        super().validate()

        regex = self.data.get("regex")
        if regex:
            error = validate_path_regex(regex)
            if error:
                self.errors.update({"regex": error})

        return self.errors
