import logging
import os.path
from datetime import timedelta
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.text import slugify
from zentral.conf import settings
from zentral.contrib.inventory.models import BaseEnrollment, MachineSnapshotCommit, MachineTag, MetaMachine
from zentral.contrib.inventory.utils import commit_machine_snapshot_and_trigger_events
from zentral.core.probes.conf import all_probes

logger = logging.getLogger("zentral.contrib.osquery.models")


SOURCE_MODULE = "zentral.contrib.osquery"
SOURCE_NAME = "osquery"


# Configuration / Enrollment


def get_or_create_machine_snapshot(serial_number, host_identifier, node_key):
    try:
        msc = (MachineSnapshotCommit.objects.filter(source__module=SOURCE_MODULE,
                                                    source__name=SOURCE_NAME,
                                                    serial_number=serial_number)
                                            .order_by("-version"))[0]
    except IndexError:
        action = 'enrollment'
        if node_key:
            # apply the enrolled machine node_key
            reference = node_key
        else:
            # old way. TODO: deprecate and remove
            # generate a new reference that we can use as node_key
            reference = get_random_string(64)
        tree = {'source': {'module': SOURCE_MODULE,
                           'name': SOURCE_NAME},
                'reference': reference,
                'serial_number': serial_number}
        if host_identifier:
            tree["system_info"] = {"computer_name": host_identifier}
    else:
        action = 're-enrollment'
        tree = msc.machine_snapshot.serialize()
        if node_key:
            # apply the enrolled machine node_key
            tree["reference"] = node_key

    return action, tree


def get_or_create_enrolled_machine(enrollment, serial_number):
    enrolled_machine, _ = EnrolledMachine.objects.get_or_create(
         enrollment=enrollment,
         serial_number=serial_number,
         defaults={"node_key": get_random_string(64)}
    )
    return enrolled_machine


def enroll(enrollment, serial_number, business_unit, host_identifier, ip):
    node_key = None
    if enrollment:
        # new way
        enrolled_machine = get_or_create_enrolled_machine(enrollment, serial_number)
        node_key = enrolled_machine.node_key

        # apply the enrollment secret tags
        for tag in enrollment.secret.tags.all():
            MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)

    # machine snapshot commit
    action, tree = get_or_create_machine_snapshot(serial_number, host_identifier, node_key)

    # update and commit the machine snapshot tree
    if business_unit:
        tree['business_unit'] = business_unit.serialize()
    if ip:
        tree["public_ip_address"] = ip
    ms = commit_machine_snapshot_and_trigger_events(tree)
    if not ms:
        logger.error("Could not commit machine snapshot tree during the osquery enrollment")

    return ms, action


class Configuration(models.Model):
    DYNAMIC_FLAGS = {
        'config_refresh',
        'distributed_interval',
    }
    STARTUP_ONLY_FLAGS = {
        'disable_carver',
        'buffered_log_max',
    }

    name = models.CharField(max_length=256, unique=True)

    config_refresh = models.IntegerField(
        validators=[MinValueValidator(60), MaxValueValidator(86400)],
        help_text=("Configuration refresh interval in seconds. If the configuration endpoint cannot be reached "
                   "during runtime, the normal retry approach is applied."),
        default=1200
    )
    distributed_interval = models.IntegerField(
        validators=[MinValueValidator(60), MaxValueValidator(86400)],
        help_text=("In seconds, the amount of time that osqueryd will wait between periodically checking in with "
                   "a distributed query server to see if there are any queries to execute."),
        default=180
    )
    disable_carver = models.BooleanField(
        help_text="Disable the osquery file carver",
        default=True
    )
    buffered_log_max = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(1000000)],
        help_text=("Maximum number of logs (status and result) "
                   "kept on disk if Zentral is unavailable "
                   "(0 = unlimited, max 1000000)"),
        default=500000
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:configuration", args=(self.pk,))

    def get_dynamic_flags(self):
        return {k: getattr(self, k) for k in self.DYNAMIC_FLAGS}

    def get_flags(self):
        flags = self.get_dynamic_flags()
        for k in self.STARTUP_ONLY_FLAGS:
            flags[k] = getattr(self, k)
        if not self.disable_carver:
            flags.update({"carver_start_endpoint": reverse('osquery:carver_start'),
                          "carver_continue_endpoint": reverse('osquery:carver_continue')})
        if self.config_refresh:
            flags["config_accelerated_refresh"] = max(60, self.config_refresh // 4)
        return flags

    def get_serialized_flag_list(self):
        return ["--{}={}".format(f, str(v).lower()) for f, v in self.get_flags().items()]

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()

    def can_be_deleted(self):
        return self.enrollment_set.all().count() == 0


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.PROTECT)
    osquery_release = models.CharField(max_length=64, blank=True, null=False)

    def get_description_for_distributor(self):
        return "Osquery configuration: {}".format(self.configuration)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = {"pk": self.configuration.pk,
                                            "name": self.configuration.name}
        if self.osquery_release:
            enrollment_dict["osquery_release"] = self.osquery_release
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("osquery:configuration", args=(self.configuration.pk,)), self.pk)


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    node_key = models.CharField(max_length=64, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


# Distributed queries


MAX_DISTRIBUTED_QUERY_AGE = timedelta(days=1)


class DistributedQueryProbeMachineManager(models.Manager):
    distributed_query_probes = all_probes.model_filter("OsqueryDistributedQueryProbe", "OsqueryFileCarveProbe")

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
        probe_list = (self.distributed_query_probes.machine_filtered(machine)
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
    probe_source = models.ForeignKey('probes.ProbeSource', on_delete=models.CASCADE)
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
    probe_source = models.ForeignKey('probes.ProbeSource', on_delete=models.CASCADE)
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
    carve_session = models.ForeignKey(CarveSession, on_delete=models.CASCADE)
    block_id = models.IntegerField()
    file = models.FileField(upload_to=carve_session_block_path)
    created_at = models.DateTimeField(auto_now_add=True)
