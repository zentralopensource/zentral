import weakref
from .models import ProbeSource


class ProbeView(object):
    def __init__(self, parent=None):
        self.parent = parent
        self._probes = None

    def clear(self):
        self._probes = None

    def iter_parent_probes(self):
        if self.parent is None:
            for p in ProbeSource.objects.active():
                yield p.load()
        else:
            yield from self.parent

    def __iter__(self):
        self._load()
        yield from self._probes

    def __len__(self):
        self._load()
        return len(self._probes)


class ProbesDict(ProbeView):
    def __init__(self, parent=None, item_func=None, unique_key=True):
        super(ProbesDict, self).__init__(parent)
        if item_func is None:
            self.item_func = lambda p: [(p.name, p)]
        else:
            self.item_func = item_func
        self.unique_key = unique_key

    def _load(self):
        if self._probes is None:
            self._probes = {}
            for probe in self.iter_parent_probes():
                for key, val in self.item_func(probe):
                    if self.unique_key:
                        self._probes[key] = val
                    else:
                        self._probes.setdefault(key, []).append(val)

    def __getitem__(self, key):
        self._load()
        return self._probes[key]

    def get(self, *args, **kwargs):
        self._load()
        return self._probes.get(*args, **kwargs)


class ProbeList(ProbeView):
    def __init__(self, parent=None, filter_func=None):
        super(ProbeList, self).__init__(parent)
        self.filter_func = filter_func
        self._children = weakref.WeakSet()

    def clear(self):
        super(ProbeList, self).clear()
        for child in self._children:
            child.clear()

    def _load(self):
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

    def class_filter(self, probe_class):
        def _filter(probe):
            return isinstance(probe, probe_class)
        return self.filter(_filter)

    def exclude_class(self, probe_class):
        def _filter(probe):
            return not isinstance(probe, probe_class)
        return self.filter(_filter)

    def inventory_filtered_probes(self, mbu_ids, tag_ids, ms_platform, ms_type):
        def _filter(probe):
            if not probe.inventory_filters:
                return True
            for inventory_filter in probe.inventory_filters:
                # tags
                f_tag_ids = set(int(tag_id)
                                for tag_id in inventory_filter.get('tags', []))
                if f_tag_ids and not f_tag_ids & tag_ids:
                    continue
                # business units
                f_mbu_ids = set(int(mbu_id)
                                for mbu_id in inventory_filter.get('business_units', []))
                if f_mbu_ids and not f_mbu_ids & mbu_ids:
                    continue
                # machine snapshot platform
                f_platforms = set(inventory_filter.get('platforms', []))
                if f_platforms and ms_platform not in f_platforms:
                    continue
                # machine snapshot type
                f_types = set(inventory_filter.get('types', []))
                if f_types and ms_type not in f_types:
                    continue
                # all tests above passed => Match
                # no need to check the other filters (OR)
                return True
            return False
        return self.filter(_filter)

    def machine_filtered(self, meta_machine):
        mbu_ids = set(mbu.id for mbu in meta_machine.meta_business_units())
        tag_ids = set(tag.id for tag in meta_machine.tags())
        return self.inventory_filtered_probes(mbu_ids, tag_ids,
                                              meta_machine.get_platform(),
                                              meta_machine.get_type())

    def module_prefix_filter(self, module_prefix):
        def _filter(probe):
            for metadata_filter in probe.metadata_filters:
                # TODO TAGS
                event_type_filter_val = metadata_filter.get("type", None)
                if event_type_filter_val is None or \
                   event_type_filter_val.startswith(module_prefix):
                    return True
            return False
        return self.filter(_filter)

all_probes = ProbeList()
