import logging
import os.path
from datetime import timedelta
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.text import slugify
from zentral.conf import settings
from zentral.contrib.inventory.models import MachineSnapshotCommit, MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.probes.conf import ProbeList

logger = logging.getLogger("zentral.contrib.osquery.models")

MAX_DISTRIBUTED_QUERY_AGE = timedelta(days=1)


def enroll(serial_number, business_unit, host_identifier, ip):
    source_module = "zentral.contrib.osquery"
    source_name = "osquery"
    try:
        msc = (MachineSnapshotCommit.objects.filter(source__name=source_name,
                                                    source__module=source_module,
                                                    serial_number=serial_number)
                                            .order_by("-version"))[0]
    except IndexError:
        action = 'enrollment'
        tree = {'source': {'module': source_module,
                           'name': source_name},
                'reference': get_random_string(64),
                'serial_number': serial_number}
        if host_identifier:
            tree["system_info"] = {"computer_name": host_identifier}
    else:
        action = 're-enrollment'
        tree = msc.machine_snapshot.serialize()
    if business_unit:
        tree['business_unit'] = business_unit.serialize()
    if ip:
        tree["public_ip_address"] = ip
    ms = commit_machine_snapshot_and_trigger_events(tree)
    if not ms:
        logger.error("Enrollment error. Could not commit tree")
    return ms, action


class DistributedQueryProbeMachineManager(models.Manager):
    def new_queries_for_machine(self, machine):
        queries = {}

        seen_probe_id = {dqpm.probe_source_id for dqpm in self.filter(machine_serial_number=machine.serial_number)}

        def probe_model_filter(probe):
            return probe.get_model() in ['OsqueryDistributedQueryProbe', 'OsqueryFileCarveProbe']

        def not_seen_probe_filter(probe):
            return probe.pk not in seen_probe_id
        min_age = timezone.now() - MAX_DISTRIBUTED_QUERY_AGE

        def recent_probe_filter(probe):
            return probe.created_at > min_age
        # TODO: slow
        # could filter the probes that are too old in the db
        probe_list = (ProbeList().filter(probe_model_filter)
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


def carve_session_dir_path(carve_session):
    return os.path.join('osquery/carves/',
                        str(carve_session.probe_source.id),
                        carve_session.machine_serial_number,
                        carve_session.session_id[:16])


def carve_session_archive_path(instance, filename):
    return os.path.join(carve_session_dir_path(instance), "archive.tar")


class CarveSession(models.Model):
    probe_source = models.ForeignKey('probes.ProbeSource')
    machine_serial_number = models.CharField(max_length=255, db_index=True)
    session_id = models.CharField(max_length=255, db_index=True)
    carve_guid = models.CharField(max_length=255, db_index=True)
    carve_size = models.BigIntegerField()
    block_size = models.IntegerField()
    block_count = models.IntegerField()
    archive = models.FileField(upload_to=carve_session_archive_path, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def get_archive_name(self):
        return "{}_{}.tar".format(slugify(self.probe_source.name),
                                  self.machine_serial_number)

    def get_archive_url(self):
        return "{}{}".format(settings["api"]["tls_hostname"],
                             reverse("osquery:download_file_carve_session_archive", args=(self.pk,)))

    def get_machine(self):
        return MetaMachine(self.machine_serial_number)

    @cached_property
    def block_number(self):
        return self.carveblock_set.count()

    @cached_property
    def progress(self):
        return self.block_number * 100 // self.block_count


def carve_session_block_path(instance, filename):
    return os.path.join(carve_session_dir_path(instance.carve_session), str(instance.block_id))


class CarveBlock(models.Model):
    carve_session = models.ForeignKey(CarveSession)
    block_id = models.IntegerField()
    file = models.FileField(upload_to=carve_session_block_path)
    created_at = models.DateTimeField(auto_now_add=True)
