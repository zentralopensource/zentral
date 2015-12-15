from datetime import datetime
import hashlib
from django.core.exceptions import FieldDoesNotExist
from django.db import models


class MTOError(Exception):
    pass


class Hasher(object):
    def __init__(self):
        self.fields = {}

    @staticmethod
    def is_empty_value(v):
        return v is None or v == [] or v == {}

    def add_field(self, k, v):
        if not isinstance(k, str) or not k:
            raise ValueError("Invalid field name {}".format(k))
        if k in self.fields:
            raise ValueError("Field {} already added".format(k))
        if self.is_empty_value(v):
            return
        elif isinstance(v, int):
            v = str(v)
        elif isinstance(v, datetime):
            v = datetime.isoformat()
        elif isinstance(v, list):
            assert(all([isinstance(e, str) and len(e) == 40 for e in v]))
        elif not isinstance(v, str):
            raise ValueError("Invalid field value {} for field {}".format(v, k))
        self.fields[k] = v

    def hexdigest(self):
        h = hashlib.sha1()
        for k in sorted(self.fields.keys()):
            v = self.fields[k]
            if isinstance(v, bytes):
                h.update(v)
            elif isinstance(v, str):
                h.update(v.encode('utf-8'))
            elif isinstance(v, list):
                for e in v:
                    h.update(e.encode('utf-8'))
        return h.hexdigest()


def prepare_commit_tree(tree):
    if not isinstance(tree, dict):
        raise MTOError("Commit tree is not a dict")
    if tree.get('mt_hash', None):
        return
    h = Hasher()
    for k, v in list(tree.items()):
        if h.is_empty_value(v):
            tree.pop(k)
        else:
            if isinstance(v, dict):
                prepare_commit_tree(v)
                v = v['mt_hash']
            elif isinstance(v, list):
                hash_list = []
                for subtree in v:
                    prepare_commit_tree(subtree)
                    hash_list.append(subtree['mt_hash'])
                v = hash_list
            h.add_field(k, v)
    tree['mt_hash'] = h.hexdigest()


class MTObjectManager(models.Manager):
    def commit(self, tree):
        prepare_commit_tree(tree)
        created = False
        try:
            obj = self.get(mt_hash=tree['mt_hash'])
        except self.model.DoesNotExist:
            obj = self.model()
            m2m_fields = []
            for k, v in tree.items():
                if k == 'mt_hash':  # special excluded field
                    obj.mt_hash = v
                elif isinstance(v, dict):
                    f = obj.get_mt_field(k, many_to_one=True)
                    fk_obj, _ = f.related_model.objects.commit(v)
                    setattr(obj, k, fk_obj)
                elif isinstance(v, list):
                    f = obj.get_mt_field(k, many_to_many=True)
                    l = []
                    for sv in v:
                        m2m_obj, _ = f.related_model.objects.commit(sv)
                        l.append(m2m_obj)
                    m2m_fields.append((k, l))
                else:
                    obj.get_mt_field(k)
                    setattr(obj, k, v)
            obj.save()
            for k, l in m2m_fields:
                setattr(obj, k, l)
            if not obj.compute_mt_hash(recursive=False) == obj.mt_hash:
                raise MTOError('Hash missmatch!!!')
            created = True
        return obj, created


class AbstractMTObject(models.Model):
    mt_hash = models.CharField(max_length=40, unique=True)
    mt_created_at = models.DateTimeField(auto_now_add=True)

    mt_excluded_fields = None

    class Meta:
        abstract = True

    objects = MTObjectManager()

    def get_mt_excluded_field_set(self):
        # TODO: memoize ? classmethod ? better ?
        l = ['id', 'mt_hash', 'mt_created_at']
        if self.mt_excluded_fields:
            l.extend(self.mt_excluded_fields)
        return set(l)

    def get_mt_field(self, name, many_to_one=None, many_to_many=None):
        if name in self.get_mt_excluded_field_set():
            raise MTOError("Field '{}' of {} is excluded".format(name,
                                                                 self._meta.object_name))
        try:
            f = self._meta.get_field(name)
        except FieldDoesNotExist as e:
            raise MTOError(str(e))
        if f.auto_created:
            raise MTOError("Field '{}' of {} auto created".format(name,
                                                                  self._meta.object_name))
        if many_to_one:
            assert(many_to_many is None)
            many_to_many = False
        if many_to_many:
            assert(many_to_one is None)
            many_to_one = False
        if f.many_to_one != many_to_one or f.many_to_many != f.many_to_many:
            raise MTOError("Field '{}' of {} has "
                           "many_to_one: {}, many_to_many: {}".format(name,
                                                                      self._meta.object_name,
                                                                      f.many_to_one, f.many_to_many))
        return f

    def _iter_mto_fields(self):
        excluded_field_set = self.get_mt_excluded_field_set()
        for f in self._meta.get_fields():
            if f.name not in excluded_field_set and not f.auto_created:
                v = getattr(self, f.name)
                if f.many_to_many:
                    v = v.all()
                yield f, v

    def compute_mt_hash(self, recursive=True):
        h = Hasher()
        for f, v in self._iter_mto_fields():
            if f.many_to_one and v:
                if recursive:
                    v = v.compute_mt_hash()
                else:
                    v = v.mt_hash
            elif f.many_to_many:
                if recursive:
                    v = [mto.compute_mt_hash() for mto in v]
                else:
                    v = [mto.mt_hash for mto in v]
            h.add_field(f.name, v)
        return h.hexdigest()

    def serialize(self):
        d = {}
        for f, v in self._iter_mto_fields():
            if f.many_to_one and v:
                v = v.serialize()
            elif f.many_to_many:
                v = [mto.serialize() for mto in v]
            elif isinstance(v, datetime):
                v = v.isoformat()
            elif v and not isinstance(v, (str, int)):
                raise ValueError("Can't serialize {}.{} value of type {}".format(self._meta.object_name,
                                                                                 f.name, type(v)))
            if Hasher.is_empty_value(v):
                continue
            else:
                d[f.name] = v
        return d
