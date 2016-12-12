import logging
from datetime import timedelta
from django.db import models
from django.utils import timezone
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import MachineSnapshotCommit
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.probes.conf import ProbeList

logger = logging.getLogger("zentral.contrib.osquery.models")

MAX_DISTRIBUTED_QUERY_AGE = timedelta(days=1)


def enroll(serial_number, business_unit, host_identifier, ip):
    tree = {'source': {'module': 'zentral.contrib.osquery',
                       'name': 'osquery'},
            'reference': get_random_string(64),
            'serial_number': serial_number}
    if business_unit:
        tree['business_unit'] = business_unit.serialize()
    if host_identifier:
        tree["system_info"] = {"computer_name": host_identifier}
    if ip:
        tree["public_ip_address"] = ip
    action = None
    ms = commit_machine_snapshot_and_trigger_events(tree)
    if not ms:
        logger.error("Enrollment error. Could not commit tree")
    else:
        if MachineSnapshotCommit.objects.filter(source=ms.source,
                                                serial_number=serial_number).count() > 1:
            # msc with same source for same serial number existed
            action = 're-enrollment'
        else:
            action = 'enrollment'
    return ms, action


class DistributedQueryProbeMachineManager(models.Manager):
    def new_queries_for_machine(self, machine):
        queries = {}

        seen_probe_id = {dqpm.probe_source_id for dqpm in self.filter(machine_serial_number=machine.serial_number)}

        def not_seen_probe_filter(probe):
            return probe.pk not in seen_probe_id
        min_age = timezone.now() - MAX_DISTRIBUTED_QUERY_AGE

        def recent_probe_filter(probe):
            return probe.created_at > min_age
        # TODO: slow
        # could filter the probes that are too old in the db
        probe_list = (ProbeList().model_filter('OsqueryDistributedQueryProbe')
                                 .machine_filtered(machine)
                                 .filter(not_seen_probe_filter)
                                 .filter(recent_probe_filter))
        for probe in probe_list:
            dqpm, created = self.get_or_create(probe_source_id=probe.pk,
                                               machine_serial_number=machine.serial_number)
            if created:
                queries[probe.distributed_query_name] = probe.distributed_query

        return queries


class DistributedQueryProbeMachine(models.Model):
    """Link a machine to a OsqueryDistributedQueryProbe

    Necessary to keep track of the distributed queries received by each machine.
    """
    probe_source = models.ForeignKey('probes.ProbeSource')
    machine_serial_number = models.CharField(max_length=255, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    objects = DistributedQueryProbeMachineManager()
