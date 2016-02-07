from datetime import timedelta
import json
from django.core.urlresolvers import reverse
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshot, MetaBusinessUnit
from zentral.utils.sql import format_sql

MAX_DISTRIBUTED_QUERY_AGE = timedelta(days=1)


def enroll(serial_number, business_unit):
    tree = {'source': {'module': 'zentral.contrib.osquery',
                       'name': 'OSQuery'},
            'reference': get_random_string(64),
            'machine': {'serial_number': serial_number}}
    if business_unit:
        tree['business_unit'] = business_unit.serialize()
    ms, _ = MachineSnapshot.objects.commit(tree)
    # TODO: check, but _ must be always true (because of the random reference)
    try:
        previous_ms = ms.mt_previous
    except MachineSnapshot.DoesNotExist:
        previous_ms = None
    if previous_ms:
        # ms with same source for same serial number existed
        return ms, 're-enrollment'
    return ms, 'enrollment'


class DistributedQuery(models.Model):
    query = models.TextField()
    meta_business_unit = models.ForeignKey(MetaBusinessUnit, blank=True, null=True, on_delete=models.SET_NULL)
    shard = models.PositiveIntegerField(default=100)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-id',)

    def get_absolute_url(self):
        return reverse('osquery:distributed', args=(self.id,))

    def can_be_updated(self):
        return self.distributedquerynode_set.count() == 0

    def serialize(self):
        d = {'query': self.query,
             'created_at': self.created_at.isoformat(),
             'shard': self.shard,
             'results': {}}
        if self.meta_business_unit:
            d['business_unit'] = str(self.meta_business_unit)
        for dqn in self.distributedquerynode_set.filter(result__isnull=False):
            d['results'][dqn.machine_serial_number] = {'result': dqn.get_json_result(),
                                                       'created_at': dqn.created_at}
        return d

    def html_query(self):
        return format_sql(self.query)

    def _make_node(self, machine_serial_number):
        dqn, _ = DistributedQueryNode.objects.get_or_create(distributed_query=self,
                                                            machine_serial_number=machine_serial_number)
        return dqn

    def make_node(self, machine_serial_number):
        if self.created_at < timezone.now() - MAX_DISTRIBUTED_QUERY_AGE or \
           self.distributedquerynode_set.filter(machine_serial_number=machine_serial_number).count():
            return
        existing_dqn_num = self.distributedquerynode_set.count()
        if self.meta_business_unit is None:
            max_dqn_num = MachineSnapshot.objects.get_current_count()
        else:
            if not self.meta_business_unit.has_machine(machine_serial_number):
                return
            max_dqn_num = self.meta_business_unit.get_machine_count()
        if self.shard / 100 * max_dqn_num > existing_dqn_num:
            return self._make_node(machine_serial_number)


class DistributedQueryNodeManager(models.Manager):
    def new_queries_with_serial_number(self, serial_number):
        dq_qs = DistributedQuery.objects.exclude(distributedquerynode__machine_serial_number=serial_number)
        l = []
        for dq in dq_qs.filter(created_at__gte=timezone.now() - MAX_DISTRIBUTED_QUERY_AGE):
            dqn = dq.make_node(serial_number)
            if dqn:
                l.append(dqn)
        return l


class DistributedQueryNode(models.Model):
    distributed_query = models.ForeignKey(DistributedQuery)
    machine_serial_number = models.CharField(max_length=255, db_index=True)
    result = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DistributedQueryNodeManager()

    def get_json_result(self):
        if self.result:
            return json.loads(self.result)

    def set_json_result(self, result_d):
        self.result = json.dumps(result_d)
        self.save()
