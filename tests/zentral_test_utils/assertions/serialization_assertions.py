import inspect
import json
from abc import ABC


class SerializeForEventAssertions(ABC):

    def assert_serialize_for_event_is_json_native(self, obj):
        """Guard that an object's event payload holds no value the stores would mangle.

        A raw datetime or UUID in a payload does not raise in production: kombu's JSON encoder
        wraps a type it does not know in a {"__type__", "__value__"} envelope instead. That
        round-trips inside Zentral but lands in the stores that dump the event themselves. The
        stdlib encoder raises on the same value, so dumping through it here trips the leak.

        Both the full and the keys_only form are checked when the serializer takes keys_only.
        """
        json.dumps(obj.serialize_for_event())
        if "keys_only" in inspect.signature(obj.serialize_for_event).parameters:
            json.dumps(obj.serialize_for_event(keys_only=True))
