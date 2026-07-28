import copy
from unittest.mock import patch

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from zentral.contrib.inventory.models import (
    BusinessUnit,
    Certificate,
    MachineGroup,
    MachineSnapshot,
    OSXApp,
    OSXAppInstance,
    Source,
)
from zentral.utils.mt_models import _NOT_CACHED, MTCommitCache, prepare_commit_tree


class MTCommitCacheTestCase(TestCase):
    maxDiff = None

    # utils

    @staticmethod
    def _source():
        return {"module": "io.zentral.tests", "name": "zentral"}

    @staticmethod
    def _certificate(common_name="Apple Root CA"):
        return {"common_name": common_name,
                "organization": "Apple Inc.",
                "organizational_unit": "Apple Certification Authority",
                "sha_1": "611e5b662c593a08ff58d14ae22452d198df6c60"}

    @staticmethod
    def _app_instance(idx, certificate):
        return {"app": {"bundle_id": f"io.zentral.app{idx}",
                        "bundle_name": f"App{idx}",
                        "bundle_version_str": f"1.{idx}"},
                "bundle_path": f"/Applications/App{idx}.app",
                # a real payload carries a distinct dict for every occurrence
                "signed_by": copy.deepcopy(certificate)}

    def _snapshot(self, app_instance_count=1, **kwargs):
        certificate = self._certificate()
        tree = {"source": self._source(),
                "serial_number": "0123456789",
                "osx_app_instances": [self._app_instance(idx, certificate)
                                      for idx in range(app_instance_count)]}
        tree.update(kwargs)
        return tree

    @staticmethod
    def _mt_hash_lookups(ctx, model):
        # only the lookups by mt_hash: the m2m fetches of hash() and full_clean() select the
        # same tables, and the quoted names keep inventory_osxapp from matching
        # inventory_osxappinstance
        table = connection.ops.quote_name(model._meta.db_table)
        column = connection.ops.quote_name("mt_hash")
        return [q["sql"] for q in ctx.captured_queries if f"WHERE {table}.{column} " in q["sql"]]

    # cache

    def test_repeated_subtrees_committed_once(self):
        tree = self._snapshot(app_instance_count=5)
        with CaptureQueriesContext(connection) as ctx:
            snapshot, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        self.assertEqual(Certificate.objects.count(), 1)
        self.assertEqual(snapshot.osx_app_instances.count(), 5)
        self.assertEqual(
            set(snapshot.osx_app_instances.values_list("signed_by", flat=True)),
            {Certificate.objects.first().pk}
        )
        # the prefetch is the only mt_hash lookup: the 5 occurrences of the certificate are cached
        self.assertEqual(len(self._mt_hash_lookups(ctx, Certificate)), 1)
        self.assertEqual(len(self._mt_hash_lookups(ctx, OSXApp)), 1)

    def test_unchanged_tree_single_query(self):
        tree = self._snapshot(app_instance_count=5)
        snapshot, created = MachineSnapshot.objects.commit(copy.deepcopy(tree))
        self.assertTrue(created)
        with CaptureQueriesContext(connection) as ctx:
            snapshot2, created2 = MachineSnapshot.objects.commit(tree)
        self.assertFalse(created2)
        self.assertEqual(snapshot, snapshot2)
        # the root hash hits: no subtree is walked, and nothing is prefetched
        self.assertEqual(len(ctx.captured_queries), 1)

    def test_existing_subtrees_prefetched(self):
        MachineSnapshot.objects.commit(self._snapshot(app_instance_count=2))
        with CaptureQueriesContext(connection) as ctx:
            snapshot, created = MachineSnapshot.objects.commit(self._snapshot(app_instance_count=3))
        self.assertTrue(created)
        self.assertEqual(Certificate.objects.count(), 1)
        self.assertEqual(OSXApp.objects.count(), 3)
        self.assertEqual(OSXAppInstance.objects.count(), 3)
        self.assertEqual(snapshot.osx_app_instances.count(), 3)
        for model in (Certificate, OSXApp, OSXAppInstance, Source):
            selects = self._mt_hash_lookups(ctx, model)
            self.assertEqual(len(selects), 1, model)
            self.assertIn("IN (", selects[0])

    def test_same_mt_hash_across_models(self):
        group_tree = {"source": self._source(), "reference": "yolo", "name": "yolo"}
        tree = self._snapshot(business_unit=copy.deepcopy(group_tree),
                              groups=[copy.deepcopy(group_tree)])
        prepared = copy.deepcopy(tree)
        prepare_commit_tree(prepared, MachineSnapshot)
        self.assertEqual(prepared["business_unit"]["mt_hash"], prepared["groups"][0]["mt_hash"])
        snapshot, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        self.assertIsInstance(snapshot.business_unit, BusinessUnit)
        self.assertEqual([type(group) for group in snapshot.groups.all()], [MachineGroup])

    def test_prefetch_chunked(self):
        tree = self._snapshot(app_instance_count=0,
                              certificates=[self._certificate(f"CA{idx}") for idx in range(3)])
        with patch("zentral.utils.mt_models.COMMIT_CACHE_CHUNK_SIZE", 1):
            with CaptureQueriesContext(connection) as ctx:
                snapshot, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        self.assertEqual(snapshot.certificates.count(), 3)
        self.assertEqual(len(self._mt_hash_lookups(ctx, Certificate)), 3)

    def test_cache_cap_falls_back_to_lookups(self):
        tree = self._snapshot(app_instance_count=5)
        with patch("zentral.utils.mt_models.MAX_COMMIT_CACHE_SIZE", 0):
            with CaptureQueriesContext(connection) as ctx:
                snapshot, created = MachineSnapshot.objects.commit(tree)
        self.assertTrue(created)
        self.assertEqual(Certificate.objects.count(), 1)
        self.assertEqual(snapshot.osx_app_instances.count(), 5)
        # nothing is cached: one lookup per occurrence of the certificate, no prefetch
        selects = self._mt_hash_lookups(ctx, Certificate)
        self.assertEqual(len(selects), 5)
        self.assertNotIn("IN (", selects[0])

    def test_cache_set_capped(self):
        cache = MTCommitCache()
        source, _ = Source.objects.commit(self._source())
        with patch("zentral.utils.mt_models.MAX_COMMIT_CACHE_SIZE", 1):
            cache.set(Source, source.mt_hash, source)
            cache.set(Certificate, "yolo", None)
        self.assertEqual(cache.get(Source, source.mt_hash), source)
        self.assertIs(cache.get(Certificate, "yolo"), _NOT_CACHED)

    def test_cache_set_upgrades_cached_absence(self):
        cache = MTCommitCache()
        source, _ = Source.objects.commit(self._source())
        cache.prefetch({Source: {source.mt_hash, "yolo"}})
        self.assertEqual(cache.get(Source, source.mt_hash), source)
        self.assertIsNone(cache.get(Source, "yolo"))
        # a capped cache still replaces a cached absence, or the object would be inserted twice
        with patch("zentral.utils.mt_models.MAX_COMMIT_CACHE_SIZE", 0):
            cache.set(Source, "yolo", source)
        self.assertEqual(cache.get(Source, "yolo"), source)

    # collector

    def test_prepare_commit_tree_collector(self):
        tree = self._snapshot(extra_facts={"un": {"deux": 3}})
        collector = {}
        prepare_commit_tree(tree, MachineSnapshot, collector)
        app_instance = tree["osx_app_instances"][0]
        self.assertEqual(collector[MachineSnapshot], {tree["mt_hash"]})
        self.assertEqual(collector[Source], {tree["source"]["mt_hash"]})
        self.assertEqual(collector[OSXAppInstance], {app_instance["mt_hash"]})
        self.assertEqual(collector[OSXApp], {app_instance["app"]["mt_hash"]})
        self.assertEqual(collector[Certificate], {app_instance["signed_by"]["mt_hash"]})
        # the JSONField subtree is hashed without a model
        self.assertNotIn(None, collector)

    def test_prepare_commit_tree_collector_skips_non_mt_model(self):
        tree = {"source": self._source(),
                "reference": "yolo",
                "name": "yolo",
                "meta_business_unit": {"name": "yolo"}}
        collector = {}
        prepare_commit_tree(tree, BusinessUnit, collector)
        self.assertEqual(set(collector), {BusinessUnit, Source})
