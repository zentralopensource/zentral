import os
import threading
import weakref
from .models import ProbeSource
from .sync import ProbeViewSync


class ProbeView(object):
    def __init__(self, parent=None, with_sync=False):
        self.parent = parent
        self._probes = None
        self._lock = threading.Lock()
        self.with_sync = with_sync
        self.sync = None

    def clear(self):
        with self._lock:
            self._probes = None

    def iter_parent_probes(self):
        if self.parent is None:
            for p in ProbeSource.objects.active():
                yield p.load()
        else:
            yield from self.parent

    def _start_sync(self):
        if self.sync is None and self.with_sync:
            # separate thread to listen to the probe change signal
            self.sync = ProbeViewSync(self)
            self.sync.start()

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
        if self._probes is None:
            self._start_sync()
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

    def clear(self):
        with self._lock:
            self._probes = None
            for child in self._children:
                child.clear()

    def _load(self):
        if self._probes is None:
            self._start_sync()
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

    def model_filter(self, *models):
        def _filter(probe):
            return probe.get_model() in models
        return self.filter(_filter)

    def class_filter(self, *probe_classes):
        def _filter(probe):
            return isinstance(probe, probe_classes)
        return self.filter(_filter)

    def machine_filtered(self, meta_machine):
        def _filter(probe):
            return probe.test_machine(meta_machine)
        return self.filter(_filter)

    def event_filtered(self, event):
        def _filter(probe):
            return probe.test_event(event)
        return self.filter(_filter)


# used for the tests, to avoid having an extra DB connection
zentral_probes_sync = os.environ.get("ZENTRAL_PROBES_SYNC", "1") == "1"


all_probes = ProbeList(with_sync=zentral_probes_sync)
