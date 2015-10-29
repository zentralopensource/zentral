from datetime import datetime, timedelta
from django.core.urlresolvers import reverse
from django.db import models, transaction, IntegrityError
from django.utils import timezone
from django.utils.crypto import get_random_string
from django_pgjson.fields import JsonField
from . import enroll_secret_secret


class EnrollError(Exception):
    pass


class NodeManager(models.Manager):
    def enroll(self, enroll_secret):
        try:
            node = self.get(enroll_secret=enroll_secret)
        except Node.DoesNotExist:
            pass
        else:
            # Re-enrollment
            return node, 're-enrollment'
        try:
            secret, method, value = enroll_secret.split('$', 2)
        except ValueError:
            raise EnrollError('Malformed enroll secret')
        if not secret == enroll_secret_secret:
            raise EnrollError('Invalid enroll secret secret')
        if not method == 'SERIAL':
            raise EnrollError('Unknown enroll secret method %s' % method)
        node = Node(enroll_secret=enroll_secret)
        for i in range(10):
            node.key = get_random_string(64)
            try:
                with transaction.atomic():
                    node.save()
            except IntegrityError:
                pass
            else:
                return node, 'enrollment'
        else:
            raise ValueError("10 key collisions")


class Node(models.Model):
    enroll_secret = models.CharField(max_length=100, unique=True)
    key = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now_add=True)
    objects = NodeManager()

    def machine_serial_number(self):
        secret, field, value = self.enroll_secret.split('$')
        if field == 'SERIAL':
            return value

    def serialize(self):
        node_d = {}
        for f in self._meta.get_fields():
            if f.concrete and (not f.is_relation or f.one_to_one or (f.many_to_one and f.related_model)):
                val = getattr(self, f.name)
                if isinstance(val, datetime):
                    val = val.isoformat()
                node_d[f.name] = val
        msn = self.machine_serial_number()
        if msn:
            node_d['machine_serial_number'] = msn
        return node_d


class DistributedQuery(models.Model):
    query = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-id',)

    def get_absolute_url(self):
        return reverse('osquery:distributed', args=(self.id,))

    def save(self, *args, **kwargs):
        super(DistributedQuery, self).save(*args, **kwargs)
        for sn in set((n.machine_serial_number() for n in Node.objects.all())):
            dqn, created = DistributedQueryNode.objects.get_or_create(distributed_query=self, machine_serial_number=sn)

    def can_be_updated(self):
        return self.distributedquerynode_set.count() == 0

    def serialize(self):
        d = {'query': self.query,
             'created_at': self.created_at.isoformat(),
             'results': {}}
        for dqn in self.distributedquerynode_set.filter(result__isnull=False):
            d['results'][dqn.machine_serial_number] = {'result': dqn.result,
                                                       'created_at': dqn.created_at}
        return d


class DistributedQueryNodeManager(models.Manager):
    MAX_QUERY_AGE = timedelta(days=1)

    def new_queries_with_serial_number(self, serial_number):
        return self.select_related('distributed_query').filter(machine_serial_number=serial_number,
                                                               result__isnull=True,
                                                               created_at__gte=timezone.now()-self.MAX_QUERY_AGE)


class DistributedQueryNode(models.Model):
    distributed_query = models.ForeignKey(DistributedQuery)
    machine_serial_number = models.CharField(max_length=255, db_index=True)
    result = JsonField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DistributedQueryNodeManager()
