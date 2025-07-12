from django.test import TestCase
from .utils import build_login_event, force_store


class TestBaseStore(TestCase):
    def test_no_event_filters_event_is_included(self):
        store = force_store()
        event = build_login_event()
        self.assertTrue(store.is_serialized_event_included(event.serialize()))

    def test_event_filters_event_is_included(self):
        store = force_store(event_filters={
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"]}],
            "excluded_event_filters": [{"routing_key": ["yolo"]}, {"event_type": ["munki_event"]}],
        })
        event = build_login_event(routing_key="jomo")
        self.assertTrue(store.is_serialized_event_included(event.serialize()))

    def test_event_filters_event_is_excluded(self):
        store = force_store(event_filters={
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"]}],
            "excluded_event_filters": [{"routing_key": ["yolo"]}, {"event_type": ["munki_event"]}],
        })
        event = build_login_event(routing_key="yolo")
        self.assertFalse(store.is_serialized_event_included(event.serialize()))
