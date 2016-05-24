import weakref
from .models import Probe


class ProbesView(object):
    def __init__(self, parent=None):
        self.parent = parent
        self._probes = None

    def clear(self):
        self._probes = None

    def iter_parent_probes(self):
        if self.parent is None:
            for p in Probe.objects.active():
                yield p.load()
        else:
            yield from self.parent

    def __iter__(self):
        self._load()
        yield from self._probes

    def __len__(self):
        self._load()
        return len(self._probes)


class ProbesDict(ProbesView):
    def __init__(self, parent=None, item_func=None, unique_key=True):
        super(ProbesDict, self).__init__(parent)
        if item_func is None:
            self.item_func = lambda p: [(p['name'], p)]
        else:
            self.item_func = item_func
        self.unique_key = unique_key

    def _load(self):
        if self._probes is None:
            self._probes = {}
            for probe_d in self.iter_parent_probes():
                for key, val in self.item_func(probe_d):
                    if self.unique_key:
                        self._probes[key] = val
                    else:
                        self._probes.setdefault(key, []).append(val)

    def __getitem__(self, key):
        self._load()
        return self._probes[key]


class ProbesList(ProbesView):
    def __init__(self, parent=None, filter_func=None):
        super(ProbesList, self).__init__(parent)
        self.filter_func = filter_func
        self._children = weakref.WeakSet()

    def clear(self):
        super(ProbesList, self).clear()
        for child in self._children:
            child.clear()

    def _load(self):
        if self._probes is None:
            self._probes = []
            for probe_d in self.iter_parent_probes():
                if self.filter_func is None or self.filter_func(probe_d):
                    self._probes.append(probe_d)

    def filter(self, filter_func):
        child = self.__class__(self, filter_func)
        self._children.add(child)
        return child

    def dict(self, item_func=None, unique_key=True):
        child = ProbesDict(self, item_func, unique_key)
        self._children.add(child)
        return child

    def inventory_filtered_probes(self, mbu_ids, tag_ids):
        def _filter(probe):
            try:
                inventory_filters = probe['filters']['inventory']
            except KeyError:
                return True
            if not inventory_filters:
                return True
            for inventory_filter in inventory_filters:
                f_tag_ids = set(int(tag_id)
                                for tag_id in inventory_filter.get('tags', []))
                if f_tag_ids and not f_tag_ids & tag_ids:
                    # filter on tags
                    # but no intersection with the given tags
                    continue
                f_mbu_ids = set(int(mbu_id)
                                for mbu_id in inventory_filter.get('business_units', []))
                if f_mbu_ids and not f_mbu_ids & mbu_ids:
                    # filter on business units
                    # but no intersection with the given business units
                    continue
                # both tests above passed. Match.
                # no need to check the other filters (OR)
                return True
            return False
        return self.filter(_filter)

    def machine_filtered_probes(self, meta_machine):
        mbu_ids = [mbu.id for mbu in meta_machine.meta_business_units()]
        tag_ids = [tag.id for tag in meta_machine.tags()]
        return self.inventory_filtered_probes(mbu_ids, tag_ids)

    def module_prefix_filter(self, module_prefix):
        def _filter(probe):
            metadata_filters = probe.get('filters', {}).get('metadata', [])
            for metadata_filter in metadata_filters:
                # TODO TAGS
                event_type_filter_val = metadata_filter.get("type", None)
                if event_type_filter_val is None or \
                   event_type_filter_val.startswith(module_prefix):
                    return True
            return False
        return self.filter(_filter)

all_probes = ProbesList()
all_probes_dict = all_probes.dict()
