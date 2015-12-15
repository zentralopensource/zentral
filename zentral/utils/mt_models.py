from datetime import datetime
import hashlib
from django.db import models


class Hasher(object):
    def __init__(self, debug_prefix=None):
        self.fields = {}
        self.debug_prefix = debug_prefix

    def add_field(self, k, v):
        if not isinstance(k, str) or not k:
            raise ValueError("Invalid field name {}".format(k))
        if k in self.fields:
            raise ValueError("Field {} already added".format(k))
        if v is None or v == []:
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
        if self.debug_prefix:
            print("<<<")
        h = hashlib.sha1()
        for k in sorted(self.fields.keys()):
            v = self.fields[k]
            if self.debug_prefix:
                print(">", self.debug_prefix, k, v)
            if isinstance(v, bytes):
                h.update(v)
            elif isinstance(v, str):
                h.update(v.encode('utf-8'))
            elif isinstance(v, list):
                for e in v:
                    h.update(e.encode('utf-8'))
        if self.debug_prefix:
            print(">>>")
        return h.hexdigest()


def prepare_mt(tree):
    assert(isinstance(tree, dict))
    if tree.get('mt_hash', None):
        return
    h = Hasher()
    for k, v in tree.items():
        if isinstance(v, dict):
            prepare_mt(v)
            v = v['mt_hash']
        elif isinstance(v, list):
            hash_list = []
            for subtree in v:
                prepare_mt(subtree)
                hash_list.append(subtree['mt_hash'])
            v = hash_list
        h.add_field(k, v)
    tree['mt_hash'] = h.hexdigest()


class MTObjectManager(models.Manager):
    def commit(self, tree):
        prepare_mt(tree)
        created = False
        try:
            obj = self.get(mt_hash=tree['mt_hash'])
        except self.model.DoesNotExist:
            obj = self.model()
            m2m_fields = []
            for k, v in tree.items():
                if isinstance(v, dict):
                    f = self.model._meta.get_field(k)
                    fk_obj, _ = f.related_model.objects.commit(v)
                    setattr(obj, k, fk_obj)
                elif isinstance(v, list):
                    f = self.model._meta.get_field(k)
                    l = []
                    for sv in v:
                        m2m_obj, _ = f.related_model.objects.commit(sv)
                        l.append(m2m_obj)
                    m2m_fields.append((k, l))
                else:
                    setattr(obj, k, v)
            obj.save()
            for k, l in m2m_fields:
                setattr(obj, k, l)
            if not obj.compute_mt_hash() == obj.mt_hash:
                raise ValueError('Hash missmatch!!!')
            created = True
        return obj, created


class AbstractMTObject(models.Model):
    mt_hash = models.CharField(max_length=40, unique=True)
    mt_created_at = models.DateTimeField(auto_now_add=True)

    mt_excluded_fields = None

    class Meta:
        abstract = True

    objects = MTObjectManager()

    @classmethod
    def get_mt_excluded_field_set(cls):
        l = ['id', 'mt_hash', 'mt_created_at']
        if cls.mt_excluded_fields:
            l.extend(cls.mt_excluded_fields)
        return set(l)

    def compute_mt_hash(self, recursive=True):
        h = Hasher()
        for f in self._meta.get_fields():
            if f.name in self._meta.model.get_mt_excluded_field_set() or f.auto_created:
                continue
            v = None
            if f.many_to_one:
                v = getattr(self, f.name)
                if v:
                    if recursive:
                        v = v.compute_mt_hash()
                    else:
                        v = v.mt_hash
            elif f.many_to_many:
                v = []
                for m2m_obj in getattr(self, f.name).all():
                    if recursive:
                        v.append(m2m_obj.compute_mt_hash())
                    else:
                        v.append(m2m_obj.mt_hash)
            else:
                v = getattr(self, f.name)
            h.add_field(f.name, v)
        return h.hexdigest()
