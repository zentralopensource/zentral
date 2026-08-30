from unittest.mock import Mock, patch

from django.test import TestCase

from zentral.core.exceptions import ImproperlyConfigured
from zentral.core.watchers import iter_watches, register_watch, watch_classes
from zentral.core.watchers.models import WatchState
from zentral.core.watchers.watches import BaseWatch
from zentral.core.watchers.workers import WatchWorker, get_workers
from zentral.utils.time import naive_utcnow


class _StubWatch(BaseWatch):
    name = "_stub_a"
    interval = 3600

    def iter_events(self, changed, recovered):
        return []

    def run_once(self):
        return 1, 2, 0


class _OtherStubWatch(_StubWatch):
    name = "_stub_b"


class _BoomWatch(_StubWatch):
    name = "_stub_boom"

    def run_once(self):
        raise RuntimeError("boom")


class _RegistryMixin:
    "setUp/tearDown only — a TestCase base would re-run every registry test in each subclass."

    def setUp(self):
        self._saved = dict(watch_classes)
        watch_classes.clear()
        for cls in (_StubWatch, _OtherStubWatch, _BoomWatch):
            watch_classes[cls.name] = cls

    def tearDown(self):
        watch_classes.clear()
        watch_classes.update(self._saved)


class RegistryTestCase(_RegistryMixin, TestCase):
    def test_register_watch(self):
        watch_classes.clear()
        register_watch(_StubWatch)
        self.assertEqual(watch_classes, {"_stub_a": _StubWatch})

    def test_register_watch_without_a_name(self):
        class _Nameless(BaseWatch):
            pass

        with self.assertRaises(ImproperlyConfigured) as cm:
            register_watch(_Nameless)
        self.assertEqual(cm.exception.message, "Watch class without a name")

    def test_register_watch_twice(self):
        with self.assertRaises(ImproperlyConfigured) as cm:
            register_watch(_StubWatch)
        self.assertEqual(cm.exception.message, 'Watch "_stub_a" already registered')

    def test_iter_watches_all_sorted(self):
        self.assertEqual([w.name for w in iter_watches()], ["_stub_a", "_stub_b", "_stub_boom"])

    def test_iter_watches_subset(self):
        self.assertEqual([w.name for w in iter_watches(["_stub_b"])], ["_stub_b"])

    def test_iter_watches_exclude(self):
        self.assertEqual([w.name for w in iter_watches(exclude={"_stub_a", "_stub_boom"})], ["_stub_b"])

    def test_iter_watches_unknown_name_is_logged_and_skipped(self):
        with self.assertLogs("zentral.core.watchers", level="ERROR") as cm:
            self.assertEqual([w.name for w in iter_watches(["_stub_nope", "_stub_b"])], ["_stub_b"])
        self.assertIn('Unknown watch "_stub_nope"', cm.output[0])


class WatchWorkerTestCase(_RegistryMixin, TestCase):
    def test_run_once_runs_the_due_watches_and_reschedules(self):
        worker = WatchWorker(watch_names=["_stub_a"])
        watches = list(iter_watches(["_stub_a"]))
        next_run_at = {"_stub_a": 0}
        worker.run_once(watches, next_run_at)
        self.assertGreater(next_run_at["_stub_a"], 0)

    def test_run_once_skips_a_watch_that_is_not_due(self):
        worker = WatchWorker(watch_names=["_stub_a"])
        watches = list(iter_watches(["_stub_a"]))
        next_run_at = {"_stub_a": 1e12}   # far in the future
        with patch.object(_StubWatch, "run_once") as run_once:
            worker.run_once(watches, next_run_at)
        self.assertEqual(run_once.call_count, 0)
        self.assertEqual(next_run_at["_stub_a"], 1e12)

    def test_a_broken_watch_does_not_stop_the_others(self):
        worker = WatchWorker(watch_names=["_stub_boom", "_stub_a"])
        watches = list(iter_watches(["_stub_boom", "_stub_a"]))
        next_run_at = {"_stub_boom": 0, "_stub_a": 0}
        with patch.object(_StubWatch, "run_once", return_value=(1, 2, 0)) as run_once:
            worker.run_once(watches, next_run_at)
        # the exception was contained, and the healthy watch still ran
        self.assertEqual(run_once.call_count, 1)

    def test_run_only_once(self):
        worker = WatchWorker(watch_names=["_stub_a"])
        with patch("zentral.core.watchers.workers.queues") as queues:
            self.assertEqual(worker.run(only_once=True), 0)
        self.assertEqual(queues.stop.call_count, 1)

    def test_run_without_a_watch_stops_immediately(self):
        worker = WatchWorker(watch_names=[])
        with patch("zentral.core.watchers.workers.queues"):
            with self.assertLogs("zentral.core.watchers.workers", level="WARNING") as cm:
                self.assertEqual(worker.run(), 0)
        self.assertIn("no watch to run", cm.output[0])

    def test_metrics(self):
        exporter = Mock()
        worker = WatchWorker(watch_names=["_stub_a"])
        with patch("zentral.core.watchers.workers.queues"):
            worker.run(metrics_exporter=exporter, only_once=True)
        exporter.start.assert_called_once()
        exporter.add_counter.assert_called_once_with("watch_transitions", ["watch", "kind"])
        exporter.inc.assert_any_call("watch_transitions", "_stub_a", "degraded", 1)
        exporter.inc.assert_any_call("watch_transitions", "_stub_a", "recovered", 2)

    def test_metrics_error_counter(self):
        exporter = Mock()
        worker = WatchWorker(watch_names=["_stub_boom"])
        with patch("zentral.core.watchers.workers.queues"):
            worker.run(metrics_exporter=exporter, only_once=True)
        exporter.inc.assert_any_call("watch_transitions", "_stub_boom", "error", 1)

    def test_sleeps_until_the_closest_deadline(self):
        # the loop is infinite by design, so break out of it from the sleep it is being tested for
        class _Stop(Exception):
            pass

        slept = []

        def fake_sleep(seconds):
            slept.append(seconds)
            raise _Stop

        worker = WatchWorker(watch_names=["_stub_a", "_stub_b"])
        with patch.object(_OtherStubWatch, "interval", 60):   # _stub_a keeps 3600
            with patch("zentral.core.watchers.workers.queues"):
                with patch("zentral.core.watchers.workers.time.sleep", side_effect=fake_sleep):
                    with self.assertRaises(_Stop):
                        worker.run()
        # both just ran, so the next deadline is the SHORTER interval — not the first, not the sum
        self.assertEqual(len(slept), 1)
        self.assertGreater(slept[0], 55)
        self.assertLessEqual(slept[0], 60)

    def test_no_metrics_exporter_is_a_no_op(self):
        worker = WatchWorker(watch_names=["_stub_a"])
        worker.inc_counter("_stub_a", "degraded", 1)   # must not raise

    def test_zero_count_is_not_reported(self):
        exporter = Mock()
        worker = WatchWorker(watch_names=["_stub_a"])
        worker.metrics_exporter = exporter
        worker.inc_counter("_stub_a", "degraded", 0)
        self.assertEqual(exporter.inc.call_count, 0)


class GetWorkersTestCase(_RegistryMixin, TestCase):
    def test_single_catch_all_worker_by_default(self):
        workers = list(get_workers())
        self.assertEqual(len(workers), 1)
        self.assertEqual(workers[0].name, "watch worker")
        self.assertIsNone(workers[0].watch_names)

    def _get_workers(self, conf):
        with patch("zentral.core.watchers.workers.settings",
                   {"apps": {"zentral.core.watchers": conf}}):
            return list(get_workers())

    def test_worker_groups(self):
        conf = {"worker_groups": [{"name": "slow", "watches": ["_stub_b"]}]}
        workers = self._get_workers(conf)
        self.assertEqual([w.name for w in workers], ["watch worker slow", "watch worker"])
        self.assertEqual(workers[0].watch_names, ["_stub_b"])
        # the catch-all excludes what the group claimed, so nothing runs twice and nothing is dropped
        self.assertIsNone(workers[1].watch_names)
        self.assertEqual(workers[1].exclude, {"_stub_b"})
        self.assertEqual([w.name for w in iter_watches(exclude=workers[1].exclude)],
                         ["_stub_a", "_stub_boom"])

    def test_a_typo_in_a_group_leaves_the_watch_to_the_catch_all(self):
        conf = {"worker_groups": [{"name": "slow", "watches": ["_stub_bb"]}]}
        workers = self._get_workers(conf)
        # the group is empty and says so, and _stub_b was excluded by a name that matches nothing
        with self.assertLogs("zentral.core.watchers", level="ERROR"):
            self.assertEqual(list(iter_watches(workers[0].watch_names)), [])
        self.assertEqual([w.name for w in iter_watches(exclude=workers[1].exclude)],
                         ["_stub_a", "_stub_b", "_stub_boom"])


class WatchStateModelTestCase(TestCase):
    def test_str(self):
        state = WatchState.objects.create(
            watch="yolo", subject_id="fomo", reasons=["stale"],
            first_fired_at=naive_utcnow(), fired_at=naive_utcnow(),
        )
        self.assertEqual(str(state), "yolo fomo")


class BaseWatchTestCase(TestCase):
    def test_a_watch_without_an_event_class_cannot_register(self):
        # core builds the events, so it has to be told what to build — caught at registration, which is
        # import time, rather than on the first tick that finds something
        class _Bare(BaseWatch):
            name = "_bare"

        with self.assertRaises(ImproperlyConfigured) as cm:
            register_watch(_Bare)
        self.assertEqual(cm.exception.message,
                         'Watch "_bare" has no event_class and does not override iter_events')

    def test_a_watch_that_builds_its_own_events_needs_no_event_class(self):
        # the door BenchmarkStalenessWatch will use: it emits only where `reasons` grew, not one per row
        class _OwnEvents(BaseWatch):
            name = "_own_events"

            def iter_events(self, changed, recovered):
                return []

        register_watch(_OwnEvents)
        self.assertIs(watch_classes["_own_events"], _OwnEvents)

    def test_fetch_without_a_result_set(self):
        # defensive: a statement with no RETURNING has no cursor description
        self.assertEqual(BaseWatch._fetch("SET LOCAL statement_timeout = 0", {}), [])
