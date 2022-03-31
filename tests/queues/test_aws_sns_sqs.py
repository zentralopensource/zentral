from django.test import SimpleTestCase
from django.utils.crypto import get_random_string
from zentral.core.queues.backends.aws_sns_sqs import build_sns_filter_policy_for_event_store
from zentral.core.stores.backends.base import BaseEventStore


class SNSFilterPolicyTestCase(SimpleTestCase):
    maxDiff = None

    @staticmethod
    def build_store(cfg=None):
        if cfg is None:
            cfg = {}
        if "store_name" not in cfg:
            cfg["store_name"] = get_random_string(12)
        return BaseEventStore(cfg)

    def test_no_event_filters_none_policy(self):
        store = self.build_store()
        self.assertIsNone(build_sns_filter_policy_for_event_store(store))

    def test_included_event_types_policy(self):
        store = self.build_store({
            "included_event_filters": [{"event_type": ["zentral_logout"]}, {"event_type": ["zentral_login"]}],
            "excluded_event_filters": [{"routing_key": ["yolo"]}, {"event_type": ["munki_event"]}],
        })
        self.assertEqual(
            build_sns_filter_policy_for_event_store(store),
            {"zentral.type": ["zentral_login", "zentral_logout"]}
        )

    def test_included_different_attributes_excluded_routing_keys_policy(self):
        store = self.build_store({
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"]},
                                       {"tags": ["un", "deux", "trois"]}],
            "excluded_event_filters": [{"routing_key": ["jomo", "yolo"]}, {"routing_key": ["fomo", "jomo"]}],
        })
        self.assertEqual(
            build_sns_filter_policy_for_event_store(store),
            {"zentral.routing_key": [{"anything-but": ["fomo", "jomo", "yolo"]}]}
        )

    def test_included_multi_attributes_excluded_routing_keys_policy(self):
        store = self.build_store({
            "included_event_filters": [{"event_type": ["zentral_login", "zentral_logout"], "tags": ["un", "deux"]}],
            "excluded_event_filters": [{"routing_key": ["jomo", "yolo"]}, {"routing_key": ["fomo", "jomo"]}],
        })
        self.assertEqual(
            build_sns_filter_policy_for_event_store(store),
            {"zentral.routing_key": [{"anything-but": ["fomo", "jomo", "yolo"]}]}
        )

    def test_no_policy_incompatible_event_store_filters(self):
        store = self.build_store({
            "excluded_event_filters": [{"event_type": ["zentral_login", "zentral_logout"], "tags": ["un", "deux"]}],
        })
        self.assertIsNone(build_sns_filter_policy_for_event_store(store))

    def test_excluded_tags_policy(self):
        store = self.build_store({
            "excluded_event_filters": [{"tags": ["jomo", "yolo"]}, {"tags": ["fomo", "jomo"]}],
        })
        self.assertEqual(
            build_sns_filter_policy_for_event_store(store),
            {"zentral.tags": [{"anything-but": ["fomo", "jomo", "yolo"]}]}
        )
