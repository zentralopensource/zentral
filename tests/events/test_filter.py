from django.test import SimpleTestCase
from accounts.events import LoginEvent
from zentral.core.events.base import EventMetadata
from zentral.core.events.filter import EventFilter


class EventFilterTestCase(SimpleTestCase):
    def test_from_str_bad_type(self):
        with self.assertRaises(TypeError) as e:
            EventFilter.from_str(3)
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Arg must be a string")

    def make_event(self, routing_key=None):
        return LoginEvent(EventMetadata(routing_key=routing_key), {"user": {"username": "yolofomo"}})

    def test_from_str_empty_string(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_str("")
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Arg must not be an empty string")

    def test_from_str_invalid_attributes_count(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_str("un:deux")
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Invalid filter attributes count")

    def test_from_str_empty_attr(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_str("un::trois")
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Empty filter event_type value")

    def test_from_str_invalid_attr(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_str("*:yolo:été meurtrier")
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Invalid filter routing_key value")

    def test_from_str(self):
        f = EventFilter.from_str("*:yolo:fomo")
        self.assertEqual(f.tag, f.WILDCARD)
        self.assertEqual(f.event_type, "yolo")
        self.assertEqual(f.routing_key, "fomo")

    def test_priority(self):
        f = EventFilter.from_str("*:yolo:fomo")
        self.assertEqual(f.priority(), 6)

    def test_eq_not_implemented(self):
        self.assertFalse(EventFilter.from_str("un:deux:trois") == 4)

    def test_eq_true(self):
        self.assertEqual(EventFilter.from_str("*:yolo:fomo"), EventFilter.from_str("*:yolo:fomo"))

    def test_eq_false(self):
        self.assertNotEqual(EventFilter.from_str("*:fomo:yolo"), EventFilter.from_str("*:yolo:fomo"))

    def test_lt_true_1(self):
        self.assertTrue(EventFilter.from_str("*:*:fomo") < EventFilter.from_str("un:*:fomo"))

    def test_lt_true_2(self):
        self.assertTrue(EventFilter.from_str("un:deux:*") < EventFilter.from_str("*:*:fomo"))

    def test_lt_false(self):
        self.assertFalse(EventFilter.from_str("a:b:*") < EventFilter.from_str("un:deux:*"))

    def test_match_event_tag(self):
        event = self.make_event(routing_key="yolo")
        self.assertTrue(EventFilter.from_str("zentral:*:*").match_event(event))

    def test_mismatch_event_tag(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(EventFilter.from_str("yolo:*:*").match_event(event))

    def test_match_event_type(self):
        event = self.make_event(routing_key="yolo")
        self.assertTrue(EventFilter.from_str("*:zentral_login:*").match_event(event))

    def test_mismatch_event_type(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(EventFilter.from_str("*:zentral_logout:*").match_event(event))

    def test_match_routing_key(self):
        event = self.make_event(routing_key="yolo")
        self.assertTrue(EventFilter.from_str("*:*:yolo").match_event(event))

    def test_mismatch_routing_key(self):
        event = self.make_event(routing_key="fomo")
        self.assertFalse(EventFilter.from_str("*:*:yolo").match_event(event))

    def test_match_wildcard(self):
        event = self.make_event()
        self.assertTrue(EventFilter.from_str("*:*:*").match_event(event))

    def test_match_serialized_event(self):
        event = self.make_event(routing_key="oui")
        self.assertTrue(EventFilter.from_str("zentral:zentral_login:oui").match_serialized_event(event.serialize()))
