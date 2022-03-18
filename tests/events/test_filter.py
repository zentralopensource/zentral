from django.test import SimpleTestCase
from accounts.events import LoginEvent
from zentral.conf.config import ConfigDict
from zentral.core.events.base import EventMetadata
from zentral.core.events.filter import EventFilter, EventFilterSet


class EventFilterTestCase(SimpleTestCase):
    def test_from_mapping_bad_type(self):
        with self.assertRaises(TypeError) as e:
            EventFilter.from_mapping(3)
        type_error = e.exception
        self.assertEqual(type_error.args[0], "from_mapping() argument must be a Mapping")

    def test_from_mapping_empty_mapping(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "from_mapping() argument must be an empty Mapping")

    def test_from_mapping_invalid_filter_attribute(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({"trois": ["yolo"]})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Invalid filter attribute: trois")

    def test_from_mapping_bad_attr_type_1(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({"event_type": 3})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "event_type value is not a valid Sequence")

    def test_from_mapping_bad_attr_type_2(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({"event_type": "zentral_login"})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "event_type value is not a valid Sequence")

    def test_from_mapping_bad_attr_type_3(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({"event_type": [3, 4]})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "event_type value is not a valid Sequence")

    def test_from_mapping_empty_attr_value(self):
        with self.assertRaises(ValueError) as e:
            EventFilter.from_mapping({"event_type": []})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "event_type value is empty")

    def test_from_mapping_1(self):
        f = EventFilter.from_mapping({"tags": ["yolo"], "event_type": ["fomo"], "routing_key": ["jomo"]})
        self.assertEqual(f.tags, frozenset(["yolo"]))
        self.assertEqual(f.event_type, frozenset(["fomo"]))
        self.assertEqual(f.routing_key, frozenset(["jomo"]))

    def test_from_mapping_2(self):
        f = EventFilter.from_mapping({"tags": ["yolo"]})
        self.assertEqual(f.tags, frozenset(["yolo"]))
        self.assertEqual(f.event_type, None)
        self.assertEqual(f.routing_key, None)

    def test_from_mapping_3(self):
        f = EventFilter.from_mapping(ConfigDict({"tags": ["yolo"]}))
        self.assertEqual(f.tags, frozenset(["yolo"]))
        self.assertEqual(f.event_type, None)
        self.assertEqual(f.routing_key, None)

    def test_match_event_tag(self):
        self.assertTrue(EventFilter.from_mapping({"tags": ["zentral", "yolo"]})
                                   .match(["zentral"], "zentral_login", "fomo"))

    def test_mismatch_event_tag(self):
        self.assertFalse(EventFilter.from_mapping({"tags": ["yolo"]})
                                    .match(["zentral"], "zentral_login", "fomo"))

    def test_match_event_type(self):
        self.assertTrue(EventFilter.from_mapping({"event_type": ["zentral_login", "yolo"]})
                                   .match(["zentral"], "zentral_login", "fomo"))

    def test_mismatch_event_type(self):
        self.assertFalse(EventFilter.from_mapping({"event_type": ["yolo"]})
                                    .match(["zentral"], "zentral_login", "fomo"))

    def test_match_routing_key(self):
        self.assertTrue(EventFilter.from_mapping({"routing_key": ["fomo", "yolo"]})
                                   .match(["zentral"], "zentral_login", "fomo"))

    def test_mismatch_routing_key(self):
        self.assertFalse(EventFilter.from_mapping({"routing_key": ["yolo"]})
                                    .match(["zentral"], "zentral_login", "fomo"))

    def test_items(self):
        self.assertEqual(
            list(
                EventFilter.from_mapping({
                    "tags": ["yolo", "fomo"],
                    "event_type": ["fomo"]
                }).items()
            ),
            [("tags", frozenset(["yolo", "fomo"])),
             ("event_type", frozenset(["fomo"]))]
        )


class EventFilterSetTestCase(SimpleTestCase):
    def make_event(self, routing_key=None):
        return LoginEvent(EventMetadata(routing_key=routing_key), {"user": {"username": "yolofomo"}})

    def test_from_mapping_bad_type(self):
        with self.assertRaises(TypeError) as e:
            EventFilterSet.from_mapping(3)
        type_error = e.exception
        self.assertEqual(type_error.args[0], "from_mapping() argument must be a Mapping")

    def test_from_mapping_bad_attr_type_1(self):
        with self.assertRaises(TypeError) as e:
            EventFilterSet.from_mapping({"included_event_filters": 1})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "included_event_filters is not a valid Sequence")

    def test_from_mapping_bad_attr_type_2(self):
        with self.assertRaises(TypeError) as e:
            EventFilterSet.from_mapping({"included_event_filters": "deux"})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "included_event_filters is not a valid Sequence")

    def test_from_mapping_empty_attr(self):
        with self.assertRaises(ValueError) as e:
            EventFilterSet.from_mapping({"included_event_filters": []})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "included_event_filters value is empty")

    def test_from_mapping_invalid_attr(self):
        with self.assertRaises(ValueError) as e:
            EventFilterSet.from_mapping({"excluded_event_filters": [{"un": 1}]})
        type_error = e.exception
        self.assertEqual(type_error.args[0], "Invalid excluded_event_filters: Invalid filter attribute: un")

    def test_from_mapping_1(self):
        fs = EventFilterSet.from_mapping({"excluded_event_filters": [{"routing_key": ["yolo"]}],
                                          "included_event_filters": [{"event_type": ["zentral_login"]}]})
        self.assertEqual(len(fs.excluded_event_filters), 1)
        self.assertIsInstance(fs.excluded_event_filters[0], EventFilter)
        self.assertEqual(fs.excluded_event_filters[0].routing_key, frozenset(["yolo"]))
        self.assertEqual(len(fs.included_event_filters), 1)
        self.assertIsInstance(fs.included_event_filters[0], EventFilter)
        self.assertEqual(fs.included_event_filters[0].event_type, frozenset(["zentral_login"]))
        self.assertTrue(bool(fs))

    def test_from_mapping_2(self):
        fs = EventFilterSet.from_mapping({})
        self.assertIsNone(fs.excluded_event_filters)
        self.assertIsNone(fs.included_event_filters)
        self.assertFalse(bool(fs))

    def test_from_mapping_3(self):
        fs = EventFilterSet.from_mapping(ConfigDict({"excluded_event_filters": [{"routing_key": ["yolo"]}],
                                                     "included_event_filters": [{"event_type": ["zentral_login"]}]}))
        self.assertEqual(len(fs.excluded_event_filters), 1)
        self.assertIsInstance(fs.excluded_event_filters[0], EventFilter)
        self.assertEqual(fs.excluded_event_filters[0].routing_key, frozenset(["yolo"]))
        self.assertEqual(len(fs.included_event_filters), 1)
        self.assertIsInstance(fs.included_event_filters[0], EventFilter)
        self.assertEqual(fs.included_event_filters[0].event_type, frozenset(["zentral_login"]))
        self.assertTrue(bool(fs))

    def test_from_mapping_4(self):
        fs = EventFilterSet.from_mapping(ConfigDict({"included_event_filters": [{"event_type": ["zentral_login"]}]}))
        self.assertIsNone(fs.excluded_event_filters)
        self.assertEqual(len(fs.included_event_filters), 1)
        self.assertIsInstance(fs.included_event_filters[0], EventFilter)
        self.assertEqual(fs.included_event_filters[0].event_type, frozenset(["zentral_login"]))
        self.assertTrue(bool(fs))

    def test_from_mapping_5(self):
        fs = EventFilterSet.from_mapping(ConfigDict({"excluded_event_filters": [{"routing_key": ["yolo"]}]}))
        self.assertEqual(len(fs.excluded_event_filters), 1)
        self.assertIsInstance(fs.excluded_event_filters[0], EventFilter)
        self.assertEqual(fs.excluded_event_filters[0].routing_key, frozenset(["yolo"]))
        self.assertIsNone(fs.included_event_filters)
        self.assertTrue(bool(fs))

    def test_empty_set_match(self):
        event = self.make_event()
        self.assertTrue(EventFilterSet.from_mapping({}).match_serialized_event(event.serialize()))

    def test_included_event_type_match(self):
        event = self.make_event()
        self.assertTrue(
            EventFilterSet.from_mapping({"included_event_filters": [{"event_type": ["zentral_login"]}]})
                          .match_serialized_event(event.serialize())
        )

    def test_not_included_event_type_mismatch(self):
        event = self.make_event()
        self.assertFalse(
            EventFilterSet.from_mapping({"included_event_filters": [{"event_type": ["zentral_logout"]}]})
                          .match_serialized_event(event.serialize())
        )

    def test_not_excluded_event_type_match(self):
        event = self.make_event()
        self.assertTrue(
            EventFilterSet.from_mapping({"excluded_event_filters": [{"event_type": ["zentral_logout"]}]})
                          .match_serialized_event(event.serialize())
        )

    def test_excluded_event_type_mismatch(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [{"routing_key": ["yolo"]}, {"tags": ["zentral"]}],
                "excluded_event_filters": [{"event_type": ["zentral_login"]}]
            }).match_serialized_event(event.serialize())
        )

    def test_included_routing_key_match(self):
        event = self.make_event(routing_key="yolo")
        self.assertTrue(
            EventFilterSet.from_mapping({
                "included_event_filters": [{"routing_key": ["yolo"]}, {"tags": ["fomo"]}],
                "excluded_event_filters": [{"event_type": ["zentral_logout"]}]
            }).match_serialized_event(event.serialize())
        )

    def test_excluded_routing_key_mismatch(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [{"routing_key": ["jomo"]}, {"tags": ["zentral"]}],
                "excluded_event_filters": [{"event_type": ["zentral_logout"]}, {"routing_key": ["yolo", "yili"]}]
            }).match_serialized_event(event.serialize())
        )

    def test_included_tags_match(self):
        event = self.make_event(routing_key="fomo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [{"routing_key": ["yolo"]}, {"tags": ["zentral"]}],
                "excluded_event_filters": [{"event_type": ["zentral_login"]}]
            }).match_serialized_event(event.serialize())
        )

    def test_excluded_tags_mismatch(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [
                    {"routing_key": ["yolo"]},
                    {"tags": ["audit"]},
                    {"event_type": ["zentral_login"]}
                ],
                "excluded_event_filters": [{"event_type": ["zentral_logout"]}, {"tags": ["zentral", "munki"]}]
            }).match_serialized_event(event.serialize())
        )

    def test_excluded_multi_mismatch(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [
                    {"routing_key": ["yolo"]},
                    {"tags": ["zentral"]},
                    {"event_type": ["zentral_login"]}
                ],
                "excluded_event_filters": [
                    {"event_type": ["zentral_login"], "routing_key": ["yolo", "fomo"], "tags": ["zentral", "munki"]},
                ],
            }).match_serialized_event(event.serialize())
        )

    def test_included_multi_match(self):
        event = self.make_event(routing_key="yolo")
        self.assertTrue(
            EventFilterSet.from_mapping({
                "included_event_filters": [
                    {"event_type": ["zentral_login"], "routing_key": ["yolo", "fomo"], "tags": ["zentral", "munki"]},
                ],
                "excluded_event_filters": [
                    {"routing_key": ["yili"]},
                ],
            }).match_serialized_event(event.serialize())
        )

    def test_not_included_multi_match(self):
        event = self.make_event(routing_key="yolo")
        self.assertFalse(
            EventFilterSet.from_mapping({
                "included_event_filters": [
                    {"event_type": ["zentral_login"], "routing_key": ["jomo", "fomo"], "tags": ["zentral", "munki"]},
                ],
                "excluded_event_filters": [
                    {"routing_key": ["yili"]},
                ],
            }).match_serialized_event(event.serialize())
        )
