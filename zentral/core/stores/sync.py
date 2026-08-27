import logging
import threading
import weakref
from django.db import connection
from base.notifier import notifier


logger = logging.getLogger("zentral.core.stores.sync")


def signal_store_change(store):
    notifier.send_notification("stores.store", str(store.pk))


class StoreWorkerConfigWatcher:
    """Stop a store worker when its store is updated or deleted.

    A worker builds its backend one time and cannot exchange it while it runs, so
    stopping is how it takes a change: the process leaves, and whatever supervises
    it starts a new one on the configuration in the database.

    The "stores.store" notification says so in a second and can be lost. Reading
    updated_at every interval_seconds always works and only every interval_seconds.
    Both call stop_worker, which therefore has to be idempotent.
    """

    interval_seconds = 300

    def __init__(self, store, stop_worker):
        self.store_pk = store.pk
        self.store_name = store.name
        self.updated_at = store.updated_at
        self.failures = 0
        self._stop_worker = stop_worker
        self._stopped = threading.Event()

    def start(self):
        # the notifier keeps the callback weakly: the with block is what holds us
        notifier.add_callback("stores.store", weakref.WeakMethod(self.handle_notification))
        # daemon: it sleeps interval_seconds at a time, stop() is the way out
        threading.Thread(target=self._run, name="store config watcher thread", daemon=True).start()

    def stop(self):
        self._stopped.set()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def handle_notification(self, *args, **kwargs):
        try:
            if str(args[0]) == str(self.store_pk):
                self._stop_for_change("notification")
        except Exception:
            logger.exception("store worker %s - could not process the store update notification", self.store_name)

    def _run(self):
        while not self._stopped.wait(self.interval_seconds):
            try:
                try:
                    changed = self.store_changed()
                finally:
                    connection.close()  # a long sleep follows, do not hold it
                if changed:
                    self._stop_for_change("interval")
            except Exception:
                # this half is the one that always arrives: a dead thread would take it away
                logger.exception("store worker %s - the store verification failed", self.store_name)

    def _stop_for_change(self, source):
        logger.warning("store worker %s - store changed, found by %s", self.store_name, source)
        # stop before the flag: a stop that raises has to leave the interval armed to try it again
        self._stop_worker()
        self._stopped.set()  # nothing left to watch

    def store_changed(self):
        from .models import Store  # avoid a circular import
        try:
            updated_at = (
                Store.objects.filter(pk=self.store_pk)
                .values_list("updated_at", flat=True)
                .first()
            )
        except Exception:
            # a worker does not need the database, keep it and count the failures
            self.failures += 1
            logger.exception("store worker %s - could not read the store, %s consecutive failure(s)",
                             self.store_name, self.failures)
            return False
        self.failures = 0
        if updated_at is None:
            # deleted: the notification stops the worker for this too, so agree
            return True
        return updated_at > self.updated_at
