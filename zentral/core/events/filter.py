from collections.abc import Mapping, Sequence


class EventFilter:
    def __init__(self, tags=None, event_type=None, routing_key=None):
        self.tags = frozenset(tags) if tags is not None else tags
        self.event_type = frozenset(event_type) if event_type is not None else event_type
        self.routing_key = frozenset(routing_key) if routing_key is not None else routing_key

    @classmethod
    def from_mapping(cls, filter_m):
        if not isinstance(filter_m, Mapping):
            raise TypeError("from_mapping() argument must be a Mapping")
        if not filter_m:
            raise ValueError("from_mapping() argument must be an empty Mapping")
        for attr, val in filter_m.items():
            if attr not in ("tags", "event_type", "routing_key"):
                raise ValueError(f"Invalid filter attribute: {attr}")
            if not isinstance(val, Sequence) or isinstance(val, str) or not all(isinstance(i, str) for i in val):
                raise ValueError(f"{attr} value is not a valid Sequence")
            if not val:
                raise ValueError(f"{attr} value is empty")
        return cls(**filter_m)

    def match(self, event_tags, event_type, event_routing_key):
        if self.tags is not None and self.tags.isdisjoint(event_tags):
            return False
        if self.event_type is not None and event_type not in self.event_type:
            return False
        if self.routing_key is not None and event_routing_key not in self.routing_key:
            return False
        return True

    def items(self):
        for attr in ("tags", "event_type", "routing_key"):
            val = getattr(self, attr)
            if val:
                yield attr, val


class EventFilterSet:
    def __init__(self, excluded_event_filters=None, included_event_filters=None):
        self.excluded_event_filters = excluded_event_filters
        self.included_event_filters = included_event_filters

    @classmethod
    def from_mapping(cls, filter_set_m):
        if not isinstance(filter_set_m, Mapping):
            raise TypeError("from_mapping() argument must be a Mapping")
        kwargs = {}
        for attr in ("included_event_filters", "excluded_event_filters"):
            try:
                val = filter_set_m[attr]
            except KeyError:
                continue
            if not val:
                raise ValueError(f"{attr} value is empty")
            if not isinstance(val, Sequence) or isinstance(val, str):
                raise TypeError(f"{attr} is not a valid Sequence")
            try:
                kwargs[attr] = [EventFilter.from_mapping(filter_m) for filter_m in val]
            except (TypeError, ValueError) as e:
                raise ValueError(f"Invalid {attr}: {e}")
        return cls(**kwargs)

    def _match(self, tags, event_type, routing_key):
        return (
            (self.excluded_event_filters is None
             or not any(f.match(tags, event_type, routing_key) for f in self.excluded_event_filters))
            and
            (self.included_event_filters is None
             or any(f.match(tags, event_type, routing_key) for f in self.included_event_filters))
        )

    def match_serialized_event(self, serialized_event):
        try:
            metadata = serialized_event["_zentral"]
            event_tags = metadata.get("tags", [])
            event_type = metadata["type"]
            event_routing_key = metadata.get("routing_key")
        except (KeyError, TypeError):
            raise ValueError("Invalid serialized event")
        return self._match(event_tags, event_type, event_routing_key)

    def __bool__(self):
        return bool(self.excluded_event_filters) or bool(self.included_event_filters)
