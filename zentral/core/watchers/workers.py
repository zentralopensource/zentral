import logging
import time

from zentral.conf import settings
from zentral.core.queues import queues

from . import iter_watches


logger = logging.getLogger("zentral.core.watchers.workers")


class WatchWorker:
    """One process for all the watches of a group.

    Scheduling is earliest-next-due, single-threaded: sleep until the closest deadline, run that watch's
    two statements, reschedule. There is nothing to rate limit *within* a run — the work is two set-based
    statements — so `interval` is the only knob.
    """
    counter_name = "watch_transitions"

    def __init__(self, name="Watch worker", watch_names=None, exclude=None):
        self.name = name
        self.watch_names = watch_names
        self.exclude = exclude
        self.metrics_exporter = None

    def inc_counter(self, watch_name, kind, count):
        if self.metrics_exporter and count:
            self.metrics_exporter.inc(self.counter_name, watch_name, kind, count)

    def run_once(self, watches, next_run_at):
        now = time.monotonic()
        due = [watch for watch in watches if next_run_at[watch.name] <= now]
        for watch in due:
            next_run_at[watch.name] = time.monotonic() + watch.interval
            try:
                changed, recovered, _ = watch.run_once()
            except Exception:
                # one broken watch must not take the others down with it: it will be retried on its next
                # interval, and convergence means the transition it missed is still there to find
                logger.exception("Watch %s: runtime error", watch.name)
                self.inc_counter(watch.name, "error", 1)
                continue
            self.inc_counter(watch.name, "degraded", changed)
            self.inc_counter(watch.name, "recovered", recovered)

    def run(self, metrics_exporter=None, only_once=False):
        self.metrics_exporter = metrics_exporter
        if self.metrics_exporter:
            self.metrics_exporter.start()
            self.metrics_exporter.add_counter(self.counter_name, ["watch", "kind"])
        watches = list(iter_watches(self.watch_names, self.exclude))
        if not watches:
            logger.warning("Worker %s: no watch to run", self.name)
        # every watch is due immediately on start, so a restart never delays a deadline
        next_run_at = {watch.name: time.monotonic() for watch in watches}
        exit_code = 0
        while True:
            self.run_once(watches, next_run_at)
            if only_once or not watches:
                break
            # sleep until the closest deadline rather than polling on a fixed tick
            time.sleep(max(0, min(next_run_at.values()) - time.monotonic()))
        queues.stop()
        return exit_code


def get_workers():
    # This declares the workers a deployment CAN run, not the ones it is running, so every watch needs a
    # worker to be deployable at all. A deployment isolates a heavy watch by declaring a group for it; the
    # default worker is then the CATCH-ALL, running whatever the groups did not claim, so registering a
    # watch never requires touching this config.
    groups = settings["apps"]["zentral.core.watchers"].get("worker_groups")
    if not groups:
        yield WatchWorker()
        return
    assigned = set()
    for group in groups:
        watch_names = list(group["watches"])
        assigned.update(watch_names)
        yield WatchWorker(name=f"Watch worker {group['name']}", watch_names=watch_names)
    yield WatchWorker(exclude=assigned)
