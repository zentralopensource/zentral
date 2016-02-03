from datetime import timedelta
import json
from django.core.urlresolvers import reverse
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshot


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
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ('-id',)

    def get_absolute_url(self):
        return reverse('osquery:distributed', args=(self.id,))

    def save(self, *args, **kwargs):
        super(DistributedQuery, self).save(*args, **kwargs)
        for ms in MachineSnapshot.objects.current().filter(source__module="zentral.contrib.osquery"):
            DistributedQueryNode.objects.get_or_create(distributed_query=self,
                                                       machine_serial_number=ms.machine.serial_number)

    def can_be_updated(self):
        return self.distributedquerynode_set.count() == 0

    def serialize(self):
        d = {'query': self.query,
             'created_at': self.created_at.isoformat(),
             'results': {}}
        for dqn in self.distributedquerynode_set.filter(result__isnull=False):
            d['results'][dqn.machine_serial_number] = {'result': dqn.get_json_result(),
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
