import re
from .base import BaseEvent


class EventFilter:
    ATTR_RE = re.compile(r'^[\w\-]+$', flags=re.ASCII)
    WILDCARD = "*"

    def __init__(self, tag, event_type, routing_key):
        self.tag = tag
        self.event_type = event_type
        self.routing_key = routing_key

    @classmethod
    def from_str(cls, filter_str):
        if not isinstance(filter_str, str):
            raise TypeError("Arg must be a string")
        if not filter_str:
            raise ValueError("Arg must not be an empty string")
        kwargs = dict(zip(("tag", "event_type", "routing_key"), filter_str.split(":")))
        if len(kwargs) != 3:
            raise ValueError("Invalid filter attributes count")
        for attr, val in kwargs.items():
            if not val:
                raise ValueError(f"Empty filter {attr} value")
            if val != cls.WILDCARD and not cls.ATTR_RE.match(val):
                raise ValueError(f"Invalid filter {attr} value")
        return cls(**kwargs)

    def _match(self, event_tags, event_type, event_routing_key):
        if self.tag != self.WILDCARD and self.tag not in event_tags:
            return False
        if self.event_type != self.WILDCARD and self.event_type != event_type:
            return False
        if self.routing_key != self.WILDCARD and self.routing_key != event_routing_key:
            return False
        return True

    def match_event(self, event):
        if not isinstance(event, BaseEvent):
            raise TypeError("Not a zentral event")
        return self._match(
            event.metadata.all_tags,
            event.event_type,
            event.metadata.routing_key
        )

    def match_serialized_event(self, serialized_event):
        try:
            metadata = serialized_event["_zentral"]
            event_tags = metadata["tags"]
            event_type = metadata["type"]
            event_routing_key = metadata["routing_key"]
        except (KeyError, TypeError):
            raise ValueError("Invalid serialized event")
        return self._match(event_tags, event_type, event_routing_key)

    def priority(self):
        return sum(
            2**idx * int(getattr(self, attr) != self.WILDCARD)
            for idx, attr in enumerate(("tag", "event_type", "routing_key"))
        )

    def __eq__(self, other):
        if not isinstance(other, EventFilter):
            return NotImplemented
        return (
            self.tag == other.tag
            and self.event_type == other.event_type
            and self.routing_key == other.routing_key
        )

    def __lt__(self, other):
        if not isinstance(other, EventFilter):
            return NotImplemented
        return self.priority() < other.priority()
