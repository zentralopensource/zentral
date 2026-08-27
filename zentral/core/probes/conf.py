import logging
import os
import threading
import time
import weakref
from base.notifier import notifier
from .models import ProbeSource
from .probe import Probe


logger = logging.getLogger("zentral.core.probes.conf")


class ProbeView(object):
    # Fallback for missed notifier notifications. Only a root uses it: a derived view
    # has no age of its own, it follows the generation of the view it is built from,
    # so the whole tree stays inside one max age whatever its depth.
    max_age_seconds = 300

    def __init__(self, parent=None, with_sync=False):
        self.parent = parent
        self._probes = None
        self._generation = 0
        self._parent_generation = None
        self._last_load_ts = None
        self._lock = threading.Lock()
        self.with_sync = with_sync
        self._sync_started = False

    def clear(self, *args, **kwargs):
        with self._lock:
            self._probes = None
            self._parent_generation = None
            self._last_load_ts = None

    def snapshot(self):
        """Version number of the probes this view serves, and the probes.

        The two come from the same critical section, so a caller can never pair a
        version with probes from a different build. The number increases on every
        build and at no other time, and clear() does not reset it, so the same
        number twice always means the same probes.

        The view builds before it answers. The probes are therefore the ones a
        reader gets now, and asking for them is what makes a view apply its own
        max age.
        """
        with self._lock:
            self._load()
            return self._generation, self._probes

    def _build_from(self):
        """The probes _build() gets, and the version number to record with them.

        The number is always the parent's own, never the root's: a view deeper in
        the tree follows the one directly above it, and each of them follows the
        one above in turn. A root has no parent and follows no version, it reads
        the database.

        A derived view takes a snapshot of its parent: one call, so the version it
        records always belongs to the probes it builds from.

        This holds our lock and takes the parent's. Child to parent is the safe
        order: clear() goes the other way, and cascades to the children after it
        has released its own lock.
        """
        if self.parent is None:
            return None, self._iter_db_probes()
        return self.parent.snapshot()

    def _iter_db_probes(self):
        # a generator function, not a generator expression: an expression evaluates
        # its outermost iterable when it is created, so the query would run here even
        # when _load() finds the cache fresh straight after and drops the rows
        for ps in ProbeSource.objects.active():
            yield Probe(ps)

    def _is_fresh(self, parent_generation):
        if self._probes is None:
            return False
        if self.parent is not None:
            return self._parent_generation == parent_generation
        return (
            self._last_load_ts is not None
            and time.monotonic() - self._last_load_ts <= self.max_age_seconds
        )

    def _load(self):
        self._start_sync()
        parent_generation, probes = self._build_from()
        if self._is_fresh(parent_generation):
            return
        # built apart and assigned in one go: a reader that holds a snapshot keeps a
        # complete set of probes, and never sees one that is half built
        self._probes = self._build(probes)
        self._parent_generation = parent_generation
        self._generation += 1
        self._last_load_ts = time.monotonic()

    def _build(self, probes):
        raise NotImplementedError

    def _start_sync(self):
        if self.with_sync:
            if not self._sync_started:
                notifier.add_callback("probes.change", weakref.WeakMethod(self.clear))
                self._sync_started = True

    def __iter__(self):
        with self._lock:
            self._load()
            yield from self._probes

    def __len__(self):
        with self._lock:
            self._load()
            return len(self._probes)


class ProbesDict(ProbeView):
    def __init__(self, parent=None, item_func=None, unique_key=True, with_sync=False):
        super(ProbesDict, self).__init__(parent, with_sync=with_sync)
        if item_func is None:
            self.item_func = lambda p: [(p.name, p)]
        else:
            self.item_func = item_func
        self.unique_key = unique_key

    def _build(self, probes):
        built = {}
        for probe in probes:
            for key, val in self.item_func(probe):
                if self.unique_key:
                    built[key] = val
                else:
                    built.setdefault(key, []).append(val)
        return built

    def __getitem__(self, key):
        with self._lock:
            self._load()
            return self._probes[key]

    def keys(self):
        with self._lock:
            self._load()
            return self._probes.keys()

    def get(self, *args, **kwargs):
        with self._lock:
            self._load()
            return self._probes.get(*args, **kwargs)


class ProbeList(ProbeView):
    def __init__(self, parent=None, filter_func=None, with_sync=False):
        super(ProbeList, self).__init__(parent, with_sync=with_sync)
        self.filter_func = filter_func
        self._children = weakref.WeakSet()

    def clear(self, *args, **kwargs):
        with self._lock:
            self._probes = None
            self._parent_generation = None
            self._last_load_ts = None
            children = list(self._children)
        # cascade outside our lock: a reader holds a child's lock while it takes a
        # snapshot of its parent (child -> parent), so taking a child's lock while
        # holding ours would invert that order and can deadlock.
        for child in children:
            child.clear()

    def _build(self, probes):
        return [
            probe for probe in probes
            if self.filter_func is None or self.filter_func(probe)
        ]

    def filter(self, filter_func):
        child = self.__class__(self, filter_func)
        self._children.add(child)
        return child

    def dict(self, item_func=None, unique_key=True):
        child = ProbesDict(self, item_func, unique_key)
        self._children.add(child)
        return child

    def event_filtered(self, event):
        def _filter(probe):
            return probe.test_event(event)
        return self.filter(_filter)


# used for the tests
zentral_probes_sync = os.environ.get("ZENTRAL_PROBES_SYNC", "1") == "1"


all_probes = ProbeList(with_sync=zentral_probes_sync)
all_probes_dict = all_probes.dict(item_func=lambda p: [(p.pk, p)], unique_key=True)
