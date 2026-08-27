from unittest.mock import patch
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string
from zentral.core.events.base import BaseEvent, EventMetadata
from zentral.core.probes.conf import all_probes, all_probes_dict, ProbeList, ProbesDict, ProbeView
from zentral.core.probes.models import ProbeSource
from zentral.core.probes.probe import Probe


class ProbesConfTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.inactive_probe_source = ProbeSource.objects.create(name=get_random_string(12),
                                                               status=ProbeSource.INACTIVE,
                                                               body={})
        cls.inactive_probe = Probe(cls.inactive_probe_source)
        cls.probe_source = ProbeSource.objects.create(name=get_random_string(12),
                                                      status=ProbeSource.ACTIVE,
                                                      body={})
        cls.probe = Probe(cls.probe_source)

    def test_all_probes(self):
        all_probes.clear()
        self.assertEqual(list(all_probes), [self.probe])

    def test_all_probes_dict(self):
        all_probes_dict.clear()
        self.assertEqual(all_probes_dict[self.probe.pk], self.probe)
        with self.assertRaises(KeyError):
            all_probes_dict[self.inactive_probe.pk]

    # _start_sync

    def test_start_sync_registers_the_callback_once(self):
        probes = ProbeList(with_sync=True)
        with patch("zentral.core.probes.conf.notifier") as notifier:
            probes._start_sync()
            probes._start_sync()
            notifier.add_callback.assert_called_once()
        self.assertTrue(probes._sync_started)

    def test_no_sync_registers_nothing(self):
        probes = ProbeList(with_sync=False)
        with patch("zentral.core.probes.conf.notifier") as notifier:
            probes._start_sync()
            notifier.add_callback.assert_not_called()
        self.assertFalse(probes._sync_started)

    # ProbesDict

    def test_probes_dict_default_item_func_keys_on_the_name(self):
        probes_dict = ProbesDict(ProbeList())
        self.assertEqual(probes_dict[self.probe_source.name], self.probe)

    def test_probes_dict_non_unique_key(self):
        probes_dict = ProbesDict(ProbeList(), item_func=lambda p: [("shared", p)], unique_key=False)
        self.assertEqual(probes_dict["shared"], [self.probe])

    def test_probes_dict_keys(self):
        probes_dict = ProbesDict(ProbeList(), item_func=lambda p: [(p.pk, p)])
        self.assertEqual(list(probes_dict.keys()), [self.probe.pk])

    def test_probes_dict_get(self):
        probes_dict = ProbesDict(ProbeList(), item_func=lambda p: [(p.pk, p)])
        self.assertEqual(probes_dict.get(self.probe.pk), self.probe)
        self.assertIsNone(probes_dict.get(self.inactive_probe.pk))

    def test_probes_dict_len(self):
        probes_dict = ProbesDict(ProbeList(), item_func=lambda p: [(p.pk, p)])
        self.assertEqual(len(probes_dict), 1)

    # ProbeList children

    def test_filter(self):
        probes = ProbeList()
        matching = probes.filter(lambda p: p.pk == self.probe.pk)
        self.assertEqual(list(matching), [self.probe])
        none_matching = probes.filter(lambda p: False)
        self.assertEqual(list(none_matching), [])

    def test_dict(self):
        probes = ProbeList()
        probes_dict = probes.dict(item_func=lambda p: [(p.pk, p)])
        self.assertEqual(probes_dict[self.probe.pk], self.probe)

    def test_event_filtered(self):
        probes = ProbeList()
        event = BaseEvent(EventMetadata(), {})
        # the probe has an empty body, so it matches every event
        self.assertEqual(list(probes.event_filtered(event)), [self.probe])

    def test_clear_cascades_to_the_children(self):
        probes = ProbeList()
        child = probes.filter(lambda p: True)
        list(child)
        self.assertIsNotNone(child._probes)
        probes.clear()
        self.assertIsNone(child._probes)
        self.assertIsNone(child._last_load_ts)

    # max age fallback

    def test_cache_is_fresh_after_load(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        list(all_probes)
        self.assertTrue(all_probes._is_fresh(None))

    def test_cache_expires(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        list(all_probes)
        all_probes._last_load_ts -= all_probes.max_age_seconds + 1
        self.assertFalse(all_probes._is_fresh(None))

    def test_clear_resets_the_load_timestamp(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        list(all_probes)
        all_probes.clear()
        self.assertIsNone(all_probes._last_load_ts)
        self.assertIsNone(all_probes_dict._last_load_ts)

    def test_child_follows_parent_expiry_when_staggered(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        self.assertEqual(all_probes_dict[self.probe.pk], self.probe)
        # the child reloads on its own while the parent is still fresh
        all_probes_dict.clear()
        self.assertEqual(all_probes_dict[self.probe.pk], self.probe)
        probe_source = ProbeSource.objects.create(name=get_random_string(12),
                                                  status=ProbeSource.ACTIVE,
                                                  body={})
        # only the parent is expired, the child's own timer is still fresh
        all_probes._last_load_ts -= all_probes.max_age_seconds + 1
        self.assertEqual(all_probes_dict[probe_source.pk], Probe(probe_source))

    def test_child_has_no_age_of_its_own(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        self.assertEqual(all_probes_dict[self.probe.pk], self.probe)
        probe_source = ProbeSource.objects.create(name=get_random_string(12),
                                                  status=ProbeSource.ACTIVE,
                                                  body={})
        # only the child is backdated: it follows the parent, which is still fresh,
        # so the new probe stays invisible and the bound is one max age, not two
        all_probes_dict._last_load_ts -= all_probes_dict.max_age_seconds + 1
        with self.assertRaises(KeyError):
            all_probes_dict[probe_source.pk]

    # snapshot

    def test_snapshot_pairs_the_generation_with_the_probes(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        generation, probes = all_probes.snapshot()
        self.assertEqual(probes, [self.probe])
        # nothing changed, so the same version and the same probes come back
        self.assertEqual(all_probes.snapshot(), (generation, probes))

    def test_snapshot_applies_the_max_age(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        generation, _ = all_probes.snapshot()
        probe_source = ProbeSource.objects.create(name=get_random_string(12),
                                                  status=ProbeSource.ACTIVE,
                                                  body={})
        all_probes._last_load_ts -= all_probes.max_age_seconds + 1
        new_generation, probes = all_probes.snapshot()
        self.assertGreater(new_generation, generation)
        self.assertIn(Probe(probe_source), probes)

    def test_generation_increases_on_every_build(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        first, _ = all_probes.snapshot()
        all_probes.clear()
        second, _ = all_probes.snapshot()
        # clear() does not reset the number, so a version is never reused
        self.assertGreater(second, first)

    def test_build_is_not_implemented_on_the_base_view(self):
        with self.assertRaises(NotImplementedError):
            ProbeView()._build([])

    def test_a_derived_view_follows_its_immediate_parent(self):
        root = ProbeList()
        child = root.filter(lambda p: True)
        grandchild = child.filter(lambda p: True)
        self.assertEqual(list(grandchild), [self.probe])
        # rebuild the middle view only: its version moves, the root's does not,
        # and the view below follows the middle one
        child.clear()
        self.assertEqual(list(grandchild), [self.probe])
        self.assertEqual(grandchild._parent_generation, child._generation)
        self.assertNotEqual(grandchild._parent_generation, root._generation)

    # database access

    def test_a_fresh_cache_makes_no_query(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        event = BaseEvent(EventMetadata(), {})
        # warm every view on the hot path
        list(all_probes)
        all_probes_dict[self.probe.pk]
        list(all_probes.event_filtered(event))
        with self.assertNumQueries(0):
            for _ in range(10):
                list(all_probes)
                all_probes_dict[self.probe.pk]
                list(all_probes.event_filtered(event))

    def test_an_expired_cache_queries_again(self):
        all_probes.clear()
        self.addCleanup(all_probes.clear)
        list(all_probes)
        all_probes._last_load_ts -= all_probes.max_age_seconds + 1
        # the count depends on the number of probes, only that it goes back matters
        with CaptureQueriesContext(connection) as queries:
            list(all_probes)
        self.assertGreater(len(queries), 0)
