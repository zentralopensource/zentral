import logging
import os
import threading
import weakref
from base.notifier import notifier
from .models import ProbeSource
from .probe import Probe


logger = logging.getLogger("zentral.core.probes.conf")


class ProbeView(object):
    def __init__(self, parent=None, with_sync=False):
        self.parent = parent
        self._probes = None
        self._lock = threading.Lock()
        self.with_sync = with_sync
        self._sync_started = False

    def clear(self, *args, **kwargs):
        with self._lock:
            self._probes = None

    def iter_parent_probes(self):
        if self.parent is None:
            for ps in ProbeSource.objects.active():
                yield Probe(ps)
        else:
            yield from self.parent

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

    def _load(self):
        self._start_sync()
        if self._probes is None:
            self._probes = {}
            for probe in self.iter_parent_probes():
                for key, val in self.item_func(probe):
                    if self.unique_key:
                        self._probes[key] = val
                    else:
                        self._probes.setdefault(key, []).append(val)

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
            for child in self._children:
                child.clear()

    def _load(self):
        self._start_sync()
        if self._probes is None:
            self._probes = []
            for probe in self.iter_parent_probes():
                if self.filter_func is None or self.filter_func(probe):
                    self._probes.append(probe)

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
