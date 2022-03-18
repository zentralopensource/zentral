from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from accounts.events import EventMetadata, LoginEvent
from zentral.conf.config import ConfigDict
from zentral.core.stores.backends.base import BaseEventStore


class TestBaseStore(SimpleTestCase):
    @staticmethod
    def build_store(cfg=None):
        if cfg is None:
            cfg = {}
        if "store_name" not in cfg:
            cfg["store_name"] = get_random_string(12)
        return BaseEventStore(cfg)

    @staticmethod
    def build_login_event(routing_key=None):
        return LoginEvent(EventMetadata(routing_key=routing_key), {"user": {"username": get_random_string(12)}})

    def test_legacy_included_event_type_event_is_included(self):
        with self.assertWarns(DeprecationWarning) as cm:
            store = self.build_store(ConfigDict({"included_event_types": ["zentral_login"]}))
        self.assertEqual(
            cm.warning.args[0],
            'included_event_types is deprecated and will be removed soon. Use included_event_filters instead.'
        )
        event = self.build_login_event()
        self.assertTrue(store.is_serialized_event_included(event.serialize()))

    def test_legacy_excluded_event_type_event_is_excluded(self):
        with self.assertWarns(DeprecationWarning) as cm:
            store = self.build_store(ConfigDict({"excluded_event_types": ["zentral_login"]}))
        self.assertEqual(
            cm.warning.args[0],
            'excluded_event_types is deprecated and will be removed soon. Use excluded_event_filters instead.'
        )
        event = self.build_login_event()
        self.assertFalse(store.is_serialized_event_included(event.serialize()))

    def test_no_event_filters_event_is_included(self):
        store = self.build_store()
        event = self.build_login_event()
        self.assertTrue(store.is_serialized_event_included(event.serialize()))

    def test_event_filters_event_is_included(self):
        store = self.build_store(ConfigDict({
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"]}],
            "excluded_event_filters": [{"routing_key": ["yolo"]}, {"event_type": ["munki_event"]}],
        }))
        event = self.build_login_event(routing_key="jomo")
        self.assertTrue(store.is_serialized_event_included(event.serialize()))

    def test_event_filters_event_is_excluded(self):
        store = self.build_store(ConfigDict({
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"]}],
            "excluded_event_filters": [{"routing_key": ["yolo"]}, {"event_type": ["munki_event"]}],
        }))
        event = self.build_login_event(routing_key="yolo")
        self.assertFalse(store.is_serialized_event_included(event.serialize()))
