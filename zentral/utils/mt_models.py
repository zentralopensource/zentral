import copy
from datetime import datetime
import hashlib
import logging
from django.core.exceptions import FieldDoesNotExist, ValidationError
from django.utils.functional import cached_property
from django.utils.timezone import is_aware, make_naive
from django.db import IntegrityError, models, transaction


logger = logging.getLogger("zentral.utils.mt_models")


_NOT_CACHED = object()

# The commit cache holds model instances, and a machine snapshot tree can carry tens of thousands
# of subtrees → cap it. Past the cap, the extra subtrees simply take the uncached path.
MAX_COMMIT_CACHE_SIZE = 10000
COMMIT_CACHE_CHUNK_SIZE = 1000


class MTOError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


class Hasher(object):
    def __init__(self):
        self.fields = {}

    @staticmethod
    def is_empty_value(v):
        return v is None or v == [] or v == {}

    def add_field(self, k, v):
        if not isinstance(k, str) or not k:
            raise ValueError(f"Invalid field name {k}")
        if k in self.fields:
            raise ValueError(f"Field {k} already added")
        if self.is_empty_value(v):
            return
        elif isinstance(v, int):
            v = str(v)
        elif isinstance(v, datetime):
            if is_aware(v):
                v = make_naive(v)
            v = v.isoformat()
        elif isinstance(v, list):
            assert(all([isinstance(e, str) and len(e) == 40 for e in v]))
        elif not isinstance(v, str):
            raise ValueError(f"Invalid field value {v} for field {k}")
        self.fields[k] = v

    def hexdigest(self):
        h = hashlib.sha1()
        for k in sorted(self.fields.keys()):
            h.update(k.encode('utf-8'))
            v = self.fields[k]
            if isinstance(v, str):
                h.update(v.encode('utf-8'))
            elif isinstance(v, list):
                for e in sorted(v):
                    h.update(e.encode('utf-8'))
        return h.hexdigest()


def _get_commit_tree_field(model, name):
    if model is None:
        return None
    try:
        f = model._meta.get_field(name)
    except FieldDoesNotExist:
        return None
    if f.auto_created or isinstance(f, models.JSONField):
        # auto created fields are rejected later in the commit method,
        # and JSONField values round-trip unchanged → their subtrees stay model-free
        return None
    return f


def prepare_commit_tree(tree, model=None, collector=None):
    if not isinstance(tree, dict):
        raise MTOError("Commit tree is not a dict")
    if tree.get('mt_hash', None):
        return
    h = Hasher()
    for k, v in list(tree.items()):
        if h.is_empty_value(v):
            tree.pop(k)
        else:
            f = _get_commit_tree_field(model, k)
            if isinstance(v, dict):
                prepare_commit_tree(v, f.related_model if f is not None and f.many_to_one else None, collector)
                v = v['mt_hash']
            elif isinstance(v, list):
                related_model = f.related_model if f is not None and f.many_to_many else None
                hash_list = []
                skipped_item_idxs = None
                for item_idx, item in enumerate(v):
                    if isinstance(item, dict):
                        prepare_commit_tree(item, related_model, collector)
                        subtree_mt_hash = item['mt_hash']
                        if subtree_mt_hash in hash_list:
                            # a list of subtrees maps to a many to many relationship, i.e. a set:
                            # a duplicated subtree carries no information and could never be committed → skip it
                            if skipped_item_idxs is None:
                                skipped_item_idxs = []
                            skipped_item_idxs.append(item_idx)
                        else:
                            hash_list.append(subtree_mt_hash)
                    else:
                        if isinstance(item, int):
                            item_to_hash = "i∅" + str(item)
                        elif isinstance(item, float):
                            item_to_hash = "f∅" + str(item)
                        elif isinstance(item, datetime):
                            if is_aware(item):
                                item = make_naive(item)
                            item_to_hash = "d∅" + item.isoformat()
                        elif isinstance(item, str):
                            item_to_hash = "s∅" + item
                        else:
                            raise MTOError("Unsupported list item type")
                        # order is important. The position in the hash list — the item index in the
                        # filtered list when subtrees have been skipped — keeps the hash consistent
                        # with the stored value.
                        item_to_hash = str(len(hash_list)) + item_to_hash
                        hash_list.append(hashlib.sha1(item_to_hash.encode('utf-8')).hexdigest())
                if skipped_item_idxs is not None:
                    logger.warning("%d duplicated subtree(s) removed from key %s", len(skipped_item_idxs), k)
                    tree[k] = [item for item_idx, item in enumerate(v) if item_idx not in skipped_item_idxs]
                v = hash_list
            elif isinstance(v, str) and isinstance(f, models.DateTimeField):
                # replace a serialized datetime with the naive datetime that will resurface
                # from the DB, so that the tree hash matches the committed object hash
                try:
                    v = f.to_python(v)
                except ValidationError:
                    raise MTOError(f'Invalid serialized datetime "{v}" for field {k}')
                if is_aware(v):
                    v = make_naive(v)
                tree[k] = v
            elif isinstance(v, datetime) and is_aware(v):
                tree[k] = v = make_naive(v)
            h.add_field(k, v)
    tree['mt_hash'] = h.hexdigest()
    # an excluded foreign key can point at a model without a mt_hash (BusinessUnit.meta_business_unit):
    # collecting it would break the prefetch
    if collector is not None and model is not None and issubclass(model, AbstractMTObject):
        collector.setdefault(model, set()).add(tree['mt_hash'])


def cleanup_commit_tree(tree):
    if not isinstance(tree, dict):
        return
    tree.pop('mt_hash', None)
    for k, v in tree.items():
        if isinstance(v, dict):
            cleanup_commit_tree(v)
        elif isinstance(v, list):
            for subtree in v:
                cleanup_commit_tree(subtree)


class MTCommitCache:
    def __init__(self):
        self._objects = {}

    def get(self, model, mt_hash):
        # the mt_hash is only unique per table: BusinessUnit and MachineGroup have the same hashable
        # fields, and a machine snapshot tree carries both → the model is part of the key
        return self._objects.get((model, mt_hash), _NOT_CACHED)

    def set(self, model, mt_hash, obj):
        key = (model, mt_hash)
        # only new keys are capped: a cached absence must always be upgraded to the committed
        # object, or the next occurrence of the subtree would try to insert it again
        if key in self._objects or len(self._objects) < MAX_COMMIT_CACHE_SIZE:
            self._objects[key] = obj

    def prefetch(self, collector):
        for model, mt_hashes in collector.items():
            free_slots = MAX_COMMIT_CACHE_SIZE - len(self._objects)
            if free_slots <= 0:
                return
            mt_hashes = sorted(mt_hashes)[:free_slots]
            for idx in range(0, len(mt_hashes), COMMIT_CACHE_CHUNK_SIZE):
                chunk = mt_hashes[idx:idx + COMMIT_CACHE_CHUNK_SIZE]
                found = {o.mt_hash: o for o in model.objects.filter(mt_hash__in=chunk)}
                for mt_hash in chunk:
                    # None caches the absence: the object can be built without a wasted query
                    self._objects[(model, mt_hash)] = found.get(mt_hash)


class MTObjectManager(models.Manager):
    def commit(self, tree, _cache=None, **extra_obj_save_kwargs):
        collector = {} if _cache is None else None
        prepare_commit_tree(tree, self.model, collector)
        mt_hash = tree['mt_hash']
        if _cache is None:
            _cache = MTCommitCache()
        cached = _cache.get(self.model, mt_hash)
        if cached is not _NOT_CACHED and cached is not None:
            return cached, False
        created = False
        obj = None
        if cached is _NOT_CACHED:
            try:
                obj = self.get(mt_hash=mt_hash)
            except self.model.DoesNotExist:
                pass
        if obj is None:
            if collector is not None:
                # an unchanged tree stops at the get above, without walking a single subtree:
                # only pay for the prefetch once the root hash has missed
                _cache.prefetch(collector)
            obj = self.model()
            m2m_fields = []
            committed_fks = []
            for k, v in tree.items():
                if k == 'mt_hash':  # special excluded field
                    obj.mt_hash = v
                elif isinstance(v, dict):
                    try:
                        f = obj.get_mt_field(k, many_to_one=True)
                    except MTOError:
                        # JSONField ???
                        f = obj.get_mt_field(k)
                        if isinstance(f, models.JSONField):
                            t = copy.deepcopy(v)
                            cleanup_commit_tree(t)
                            setattr(obj, k, t)
                        else:
                            raise MTOError(f'Cannot set field "{k}" to dict value')
                    else:
                        fk_obj, _ = f.related_model.objects.commit(v, _cache=_cache)
                        setattr(obj, k, fk_obj)
                        committed_fks.append(k)
                elif isinstance(v, list):
                    f = obj.get_mt_field(k, many_to_many=True)
                    ol = []
                    for sv in v:
                        m2m_obj, _ = f.related_model.objects.commit(sv, _cache=_cache)
                        ol.append(m2m_obj)
                    m2m_fields.append((k, ol))
                else:
                    obj.get_mt_field(k)
                    setattr(obj, k, v)
            try:
                with transaction.atomic():
                    obj.save(**extra_obj_save_kwargs)
                    for k, l in m2m_fields:
                        getattr(obj, k).set(l)
                    # full_clean runs after a successful insert, so every unique constraint has
                    # already been enforced by the DB, and the foreign keys committed above exist
                    # by construction → both checks are queries that cannot fail
                    obj.full_clean(exclude=committed_fks, validate_unique=False)
            except IntegrityError as integrity_error:
                # the object has been concurrently created ?
                try:
                    obj = self.get(mt_hash=mt_hash)
                except self.model.DoesNotExist:
                    # that was not a key error:
                    raise integrity_error
            else:
                if not obj.hash(recursive=False) == obj.mt_hash:
                    raise MTOError(f'Obj {obj} Hash missmatch!!!')
                created = True
        _cache.set(self.model, mt_hash, obj)
        return obj, created


class AbstractMTObject(models.Model):
    mt_hash = models.CharField(max_length=40, unique=True)
    mt_created_at = models.DateTimeField(auto_now_add=True)
    mt_excluded_fields = None

    class Meta:
        abstract = True

    objects = MTObjectManager()

    @cached_property
    def mt_excluded_field_set(self):
        efs = {'id', 'mt_hash', 'mt_created_at'}
        if self.mt_excluded_fields:
            efs.update(self.mt_excluded_fields)
        return efs

    def get_mt_field(self, name, many_to_one=None, many_to_many=None):
        if name in self.mt_excluded_field_set:
            raise MTOError(f"Field '{name}' of {self._meta.object_name} is excluded")
        try:
            f = self._meta.get_field(name)
        except FieldDoesNotExist as e:
            raise MTOError(str(e))
        if f.auto_created:
            raise MTOError(f"Field '{name}' of {self._meta.object_name} auto created")
        if many_to_one:
            assert(many_to_many is None)
            many_to_many = False
        if many_to_many:
            assert(many_to_one is None)
            many_to_one = False
        if f.many_to_one != many_to_one or f.many_to_many != many_to_many:
            raise MTOError(f"Field '{name}' of {self._meta.object_name} has "
                           f"many_to_one: {f.many_to_one}, many_to_many: {f.many_to_many}")
        return f

    def _iter_mto_fields(self):
        for f in self._meta.get_fields():
            if f.name not in self.mt_excluded_field_set and not f.auto_created:
                v = getattr(self, f.name)
                if f.many_to_many:
                    v = v.all()
                yield f, v

    def hash(self, recursive=True):
        h = Hasher()
        for f, v in self._iter_mto_fields():
            if f.many_to_one and v:
                if recursive:
                    v = v.hash()
                else:
                    v = v.mt_hash
            elif f.many_to_many:
                if recursive:
                    v = [mto.hash() for mto in v]
                else:
                    v = [mto.mt_hash for mto in v]
            elif isinstance(f, models.JSONField) and v:
                t = copy.deepcopy(v)
                prepare_commit_tree(t)
                v = t['mt_hash']
            h.add_field(f.name, v)
        return h.hexdigest()

    def serialize(self, exclude=None):
        d = {}
        for f, v in self._iter_mto_fields():
            if exclude and f.name in exclude:
                continue
            if f.many_to_one and v:
                v = v.serialize()
            elif f.many_to_many:
                v = [mto.serialize() for mto in v]
            elif isinstance(v, datetime):
                v = v.isoformat()
            elif v and not isinstance(v, (str, int, dict)):
                raise ValueError(f"Can't serialize {self._meta.object_name}.{f.name} value of type {type(v)}")
            if Hasher.is_empty_value(v):
                continue
            else:
                d[f.name] = v
        return d

    def diff(self, mto):
        if mto._meta.model != self._meta.model:
            raise MTOError("Can only compare to an object of the same model")
        diff = {}
        # if same objects or same hash, we can optimize and return an empty diff
        if self == mto or self.mt_hash == mto.mt_hash:
            return diff
        for f, v in self._iter_mto_fields():
            fdiff = {}
            if f.many_to_many:
                mto_v_qs = getattr(mto, f.name).all()
                # TODO: better
                for o in v.exclude(pk__in=[o.id for o in mto_v_qs]):
                    fdiff.setdefault('added', []).append(o.serialize())
                for o in mto_v_qs.exclude(pk__in=[o.id for o in v]):
                    fdiff.setdefault('removed', []).append(o.serialize())
            else:
                mto_v = getattr(mto, f.name)
                if v != mto_v:
                    if isinstance(v, AbstractMTObject):
                        v = v.serialize()
                    if isinstance(mto_v, AbstractMTObject):
                        mto_v = mto_v.serialize()
                    if mto_v:
                        fdiff['removed'] = mto_v
                    if v:
                        fdiff['added'] = v
            if fdiff:
                diff[f.name] = fdiff
        return diff
