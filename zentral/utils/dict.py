import copy
from functools import reduce
import operator


def dict_diff(d1, d2):
    diff = {}
    for k1, v1 in d1.items():
        kdiff = {}
        if isinstance(v1, list):
            v2 = d2.get(k1, [])
            added = [v2i for v2i in v2 if v2i not in v1]
            if added:
                kdiff["added"] = added
            removed = [v1i for v1i in v1 if v1i not in v2]
            if removed:
                kdiff["removed"] = removed
        else:
            v2 = d2.get(k1, None)
            if v1 != v2:
                if v1 is not None:
                    kdiff["removed"] = v1
                if v2 is not None:
                    kdiff["added"] = v2
        if kdiff:
            diff[k1] = kdiff
    for k2, v2 in d2.items():
        if k2 in d1 or v2 is None:
            continue
        diff[k2] = {"added": v2}
    return copy.deepcopy(diff)


def get_nested_val(d, key, separator="."):
    try:
        return reduce(operator.getitem, key.split(separator), d)
    except (KeyError, TypeError):
        return None
