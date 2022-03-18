from django.test import SimpleTestCase
from zentral.core.events.filter import EventFilter


class EventFilterTestCase(SimpleTestCase):
    def test_from_str_bad_type(self):
        with self.assertRaises(TypeError) as e:
            EventFilter.from_str(3)
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Arg must be a string")

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
