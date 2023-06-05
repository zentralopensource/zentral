import enum
import logging
import os.path
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.db import models, connection
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from zentral.conf import settings
from zentral.contrib.inventory.models import BaseEnrollment, Tag
from zentral.utils.sql import tables_in_query, format_sql
from zentral.utils.text import shard
from .specs import cli_only_flags


logger = logging.getLogger("zentral.contrib.osquery.models")


SOURCE_MODULE = "zentral.contrib.osquery"
SOURCE_NAME = "osquery"


# Configuration


class Platform(enum.Enum):
    # https://osquery.readthedocs.io/en/stable/deployment/configuration/#schedule
    DARWIN = ("darwin", 0x10)  # for macOS hosts
    FREEBSD = ("freebsd", 0x20)  # or FreeBSD hosts
    LINUX = ("linux", 0x08)  # for any RedHat or Debian-based hosts
    POSIX = ("posix", 0x01)  # darwin or freebsd or linux
    WINDOWS = ("windows", 0x02)  # for any Windows desktop or server hosts

    @classmethod
    def choices(cls):
        return tuple((i.value[0], i.value[0]) for i in cls)

    @classmethod
    def accepted_platforms(cls):
        return set(i.value[0] for i in cls)

    @classmethod
    def platforms_from_mask(cls, mask):
        platforms = []
        for i in cls:
            if i.value[1] & mask:
                platforms.append(i.value[0])
        return platforms


osquery_version_validator = RegexValidator(r"^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,4})?$")


class Query(models.Model):
    name = models.CharField(max_length=256, unique=True)

    sql = models.TextField()

    platforms = ArrayField(
        models.CharField(max_length=32, choices=Platform.choices()),
        blank=True,
        default=list,
        help_text="Restrict this query to some platforms, default is 'all' platforms"
    )
    minimum_osquery_version = models.CharField(
        max_length=14,
        validators=[osquery_version_validator],
        null=True,
        blank=True,
        help_text="This query will only execute on osquery versions greater than or equal-to this version string"
    )

    description = models.TextField(blank=True)
    value = models.TextField(blank=True)

    version = models.PositiveIntegerField(default=1, editable=False)

    compliance_check = models.OneToOneField(
        "compliance_checks.ComplianceCheck",
        on_delete=models.SET_NULL,
        related_name="query",
        editable=False,
        null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:query", args=(self.pk,))

    def get_sql_html(self):
        return format_sql(self.sql)

    @cached_property
    def tables(self):
        return sorted(tables_in_query(self.sql))

    def serialize(self):
        d = {"query": self.sql}
        if self.platforms:
            d["platform"] = ",".join(self.platforms)
        if self.minimum_osquery_version:
            d["version"] = self.minimum_osquery_version
        return d

    def serialize_for_event(self):
        d = {"sql": self.sql,
             "version": self.version}
        if self.platforms:
            d["platform"] = ",".join(self.platforms)
        if self.minimum_osquery_version:
            d["version"] = self.minimum_osquery_version
        if self.description:
            d["description"] = self.description
        if self.value:
            d["value"] = self.value
        return d

    def delete(self, *args, **kwargs):
        if self.compliance_check:
            self.compliance_check.delete()
        return super().delete(*args, **kwargs)

    def compliance_check_enabled(self):
        return True if self.compliance_check else False


class Pack(models.Model):
    DELIMITER = "/"

    name = models.CharField(max_length=256, unique=True)
    slug = models.CharField(max_length=256, unique=True, editable=False)
    description = models.TextField(blank=True)

    discovery_queries = ArrayField(
        models.TextField(),
        blank=True,
        default=list,
        help_text="This pack will only execute if all discovery queries return results."
    )
    shard = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        null=True,
        blank=True,
        help_text="Restrict every pack queries to a percentage (1-100) of target hosts"
    )

    event_routing_key = models.SlugField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:pack", args=(self.pk,))

    def configuration_key(self):
        return f"{self.slug}{self.DELIMITER}{self.pk}"

    def serialize(self):
        d = {"queries": {pq.pack_key(): pq.serialize()
                         for pq in self.packquery_set.select_related("query").all()}}
        if self.discovery_queries:
            d["discovery"] = self.discovery_queries
        if self.shard and self.shard != 100:
            d["shard"] = self.shard
        return d

    def serialize_for_event(self, short=False):
        d = {"pk": self.pk,
             "slug": self.slug}
        if short:
            return d
        d["name"] = self.name
        if self.discovery_queries:
            d["discovery_queries"] = self.discovery_queries
        if self.shard:
            d["shard"] = self.shard
        return d


def parse_pack_query_configuration_key(key):
    try:
        items = key.split(Pack.DELIMITER)
        if len(items) == 6:
            _, pack_pk, _, query_pk, query_version, event_routing_key = items
        else:
            _, pack_pk, _, query_pk, query_version = items
            event_routing_key = None
        pack_pk = int(pack_pk)
        query_pk = int(query_pk)
        query_version = int(query_version)
    except (AttributeError, ValueError):
        raise ValueError("Not an osquery pack query configuration key")
    return pack_pk, query_pk, query_version, event_routing_key


def parse_result_name(name):
    expected_prefix = "pack" + Pack.DELIMITER
    if not name.startswith(expected_prefix):
        raise ValueError("result query name doesn't start with expected prefix")
    configuration_key = name[len(expected_prefix):]
    return parse_pack_query_configuration_key(configuration_key)


class PackQueryManager(models.Manager):
    def get_with_config_key(self, key):
        pack_pk, query_pk, _, _ = parse_pack_query_configuration_key(key)
        return self.get(pack__pk=pack_pk, query__pk=query_pk)


class PackQuery(models.Model):
    pack = models.ForeignKey(Pack, on_delete=models.CASCADE, editable=False)
    query = models.OneToOneField(Query, on_delete=models.CASCADE)
    slug = models.CharField(max_length=256, editable=False)

    interval = models.IntegerField(
        validators=[MinValueValidator(10),  # 10s
                    MaxValueValidator(604800)],  # 7d
        help_text="interval in seconds to run the query (subject to splay/smoothing)"
    )
    log_removed_actions = models.BooleanField(
        default=True,
        help_text="If 'removed' action should be logged"
    )
    snapshot_mode = models.BooleanField(
        default=False,
        help_text="Run this query in 'snapshot' mode"
    )
    shard = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        null=True,
        blank=True,
        help_text="restrict this query to a percentage (1-100) of target hosts"
    )
    can_be_denylisted = models.BooleanField(
        default=True,
        help_text="If this query can be denylisted when stopped for excessive resource consumption."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = PackQueryManager()

    class Meta:
        unique_together = (("pack", "slug"),)

    def get_absolute_url(self):
        return "{}#pq{}".format(self.pack.get_absolute_url(), self.pk)

    def pack_key(self):
        items = [self.slug, str(self.query.pk), str(self.query.version)]
        if self.pack.event_routing_key:
            items.append(self.pack.event_routing_key)
        return Pack.DELIMITER.join(items)

    def serialize(self):
        d = self.query.serialize()
        d["interval"] = self.interval
        if not self.log_removed_actions:
            d["removed"] = False
        if self.snapshot_mode:
            d["snapshot"] = True
        if self.shard and self.shard != 100:
            d["shard"] = self.shard
        if not self.can_be_denylisted:
            d["denylist"] = False
        return d

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "slug": self.slug,
             "pack": self.pack.serialize_for_event(short=True),
             "query": self.query.serialize_for_event(),
             "interval": self.interval,
             "log_removed_actions": self.log_removed_actions,
             "snapshot_mode": self.snapshot_mode,
             "can_be_denylisted": self.can_be_denylisted}
        if self.shard and self.shard != 100:
            d["shard"] = self.shard
        return d


class FileCategory(models.Model):
    name = models.CharField(max_length=256, unique=True)
    slug = models.CharField(max_length=256, unique=True, editable=False)
    description = models.TextField(blank=True)

    file_paths = ArrayField(models.CharField(max_length=256), blank=True, default=list)
    exclude_paths = ArrayField(models.CharField(max_length=256), blank=True, default=list)
    file_paths_queries = ArrayField(models.TextField(), blank=True, default=list)
    access_monitoring = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:file_category", args=(self.pk,))


class AutomaticTableConstruction(models.Model):
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)

    table_name = models.CharField(
        max_length=64, unique=True,
        validators=[RegexValidator(r"[a-z_]+")]
    )
    query = models.TextField()
    path = models.CharField(max_length=256)
    columns = ArrayField(models.CharField(max_length=64, validators=[RegexValidator(r"[a-z_]")]))
    platforms = ArrayField(
        models.CharField(max_length=32, choices=Platform.choices()),
        blank=True,
        default=list,
        help_text="Restrict this automatic table construction to some platforms, default is 'all' platforms"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:atc", args=(self.pk,))

    def get_query_html(self):
        return format_sql(self.query)


class Configuration(models.Model):
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)

    inventory = models.BooleanField(
        default=True,
        help_text="Schedule regular inventory queries"
    )
    inventory_apps = models.BooleanField(
        default=False,
        help_text="Include executables (apps/programs) or linux packages in the inventory"
    )
    inventory_ec2 = models.BooleanField(
        default=False,
        help_text="Include AWS EC2 information in the inventory",
        verbose_name="Inventory EC2 information"
    )
    inventory_interval = models.IntegerField(
        default=86400,  # 1d
        validators=[MinValueValidator(300),  # 5m
                    MaxValueValidator(172800)],  # 2d
        help_text="Inventory refresh interval in seconds"
    )

    options = models.JSONField(default=dict, blank=True, help_text="Osquery options")

    file_categories = models.ManyToManyField(FileCategory, blank=True)
    automatic_table_constructions = models.ManyToManyField(AutomaticTableConstruction, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("osquery:configuration", args=(self.pk,))

    def get_all_flags(self):
        flags = {
            "tls_hostname": settings["api"]["fqdn"],

            # tls config every 1200s
            "config_plugin": "tls",
            "config_tls_endpoint": reverse("osquery_public:config"),
            "config_refresh": 1200,

            # distributed queries enabled with a 60s interval
            "disable_distributed": False,
            "distributed_plugin": "tls",
            "distributed_interval": 60,
            "distributed_tls_read_endpoint": reverse("osquery_public:distributed_read"),
            "distributed_tls_write_endpoint": reverse("osquery_public:distributed_write"),

            # force tls enrollment
            "disable_enrollment": False,
            "enroll_tls_endpoint": reverse("osquery_public:enroll"),

            # tls logger with a 60s period, and compression
            "logger_plugin": "tls",
            "logger_tls_endpoint": reverse("osquery_public:log"),
            "logger_tls_period": 60,
            "logger_tls_compress": True,
        }
        flags.update(self.options)
        if not flags.get("disable_carver", True) or not flags.get("carver_disable_function", True):
            flags.update({
                "carver_disable_function": False,
                "disable_carver": False,
                "carver_continue_endpoint": reverse("osquery_public:carver_continue"),
                "carver_start_endpoint": reverse("osquery_public:carver_start"),
                "carver_compression": False,  # TODO: implement!
            })
        # Forced because we need the Osquery API views to work
        flags["pack_delimiter"] = Pack.DELIMITER
        return flags

    def serialize_options(self):
        return {k: v for k, v in self.get_all_flags().items() if k not in cli_only_flags}

    def get_serialized_flags(self):
        flags = []
        for k, v in self.get_all_flags().items():
            if isinstance(v, bool):
                v = str(v).lower()
            flags.append(f"--{k}={v}")
        return flags

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()

    def can_be_deleted(self):
        return self.enrollment_set.all().count() == 0


class ConfigurationPack(models.Model):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE, editable=False)
    pack = models.ForeignKey(Pack, on_delete=models.CASCADE)
    tags = models.ManyToManyField(Tag, blank=True)

    class Meta:
        unique_together = (("configuration", "pack"),)

    def get_absolute_url(self):
        return "{}#cp{}".format(self.configuration.get_absolute_url(), self.pk)


# Enrollment


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


class EnrolledMachineManager(models.Manager):
    def get_for_serial_number(self, serial_number):
        return list(
            self.select_related("enrollment__configuration")
            .filter(serial_number=serial_number)
            .order_by("-updated_at")
        )


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)

    serial_number = models.TextField(db_index=True)
    node_key = models.CharField(max_length=64, unique=True)
    osquery_version = models.CharField(max_length=14, blank=True, null=True)
    platform_mask = models.PositiveSmallIntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrolledMachineManager()

    class Meta:
        unique_together = (("enrollment", "serial_number"),)

    @property
    def platforms(self):
        return Platform.platforms_from_mask(self.platform_mask)

    @cached_property
    def osquery_version_tuple(self):
        if self.osquery_version:
            return tuple(int(v) for v in self.osquery_version.split("."))
        else:
            return (0, 0, 0)


# Distributed queries


class DistributedQueryManager(models.Manager):
    def active(self):
        now = timezone.now()
        return (
            self.filter(Q(valid_until__isnull=True) | Q(valid_until__gte=now))
                .filter(valid_from__lte=now)
        )

    def iter_queries_for_enrolled_machine(self, enrolled_machine, tags):
        serial_number = enrolled_machine.serial_number
        qs = (
            self.active()
                .distinct()
                .filter(Q(platforms__len=0) | Q(platforms__overlap=enrolled_machine.platforms))
                .filter(Q(serial_numbers__len=0) | Q(serial_numbers__contains=[serial_number]))
                .filter(Q(tags__isnull=True) | Q(tags__in=tags))
                .exclude(distributedquerymachine__serial_number=serial_number)
                .order_by("pk")
        )
        for dq in qs:
            # min osquery version verification
            if dq.minimum_osquery_version_tuple > enrolled_machine.osquery_version_tuple:
                continue
            # consistant sharding per dq and serial number
            if dq.shard == 100 or shard(serial_number, dq.pk) <= dq.shard:
                yield dq


class DistributedQuery(models.Model):
    query = models.ForeignKey(Query, on_delete=models.SET_NULL, null=True, editable=False)
    query_version = models.IntegerField(editable=False)
    sql = models.TextField(editable=False)
    platforms = ArrayField(
        models.CharField(max_length=32, choices=Platform.choices()),
        editable=False,
        default=list
    )
    minimum_osquery_version = models.CharField(
        max_length=14,
        validators=[osquery_version_validator],
        editable=False,
        null=True,
    )

    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField(blank=True, null=True)

    serial_numbers = ArrayField(models.TextField(), blank=True, default=list)
    tags = models.ManyToManyField(Tag, blank=True)
    shard = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(100)],
        default=100,
        help_text="Restrict this query to a percentage (1-100) of target hosts"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DistributedQueryManager()

    def __str__(self):
        return str(self.pk)

    def get_absolute_url(self):
        return reverse("osquery:distributed_query", args=(self.pk,))

    def get_sql_html(self):
        return format_sql(self.sql)

    @cached_property
    def tables(self):
        return sorted(tables_in_query(self.sql))

    def is_active(self):
        now = timezone.now()
        if self.valid_from > now:
            return False
        if self.valid_until and self.valid_until < now:
            return False
        return True

    @property
    def minimum_osquery_version_tuple(self):
        if self.minimum_osquery_version:
            return tuple(int(v) for v in self.minimum_osquery_version.split("."))
        else:
            return (0, 0, 0)

    def result_columns(self):
        query = (
            "select distinct jsonb_object_keys(row) as col "
            "from osquery_distributedqueryresult where distributed_query_id = %s "
            "order by col"
        )
        cursor = connection.cursor()
        cursor.execute(query, [self.pk])
        return [t[0] for t in cursor.fetchall()]


class DistributedQueryMachine(models.Model):
    distributed_query = models.ForeignKey(DistributedQuery, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)

    status = models.IntegerField(null=True)
    error_message = models.TextField(null=True)

    memory = models.BigIntegerField(null=True)
    system_time = models.BigIntegerField(null=True)
    user_time = models.BigIntegerField(null=True)
    wall_time_ms = models.BigIntegerField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("distributed_query", "serial_number"),)


class DistributedQueryResult(models.Model):
    distributed_query = models.ForeignKey(DistributedQuery, on_delete=models.CASCADE)
    serial_number = models.TextField()
    row = models.JSONField()

    class Meta:
        indexes = [
            models.Index(fields=["distributed_query", "serial_number"])
        ]

    def iter_row_kv(self):
        if not isinstance(self.row, dict):
            return
        for k in sorted(self.row.keys()):
            yield k, self.row.get(k)


# File carving


def file_carving_session_dir_path(file_carving_session):
    if file_carving_session.distributed_query_id:
        subpath = f"runs/{file_carving_session.distributed_query_id}"
    elif file_carving_session.pack_query_id:
        subpath = f"scheduled/{file_carving_session.pack_query_id}"
    else:
        # should never happend
        subpath = "orphans"
    return os.path.join('osquery/file_carvings/', subpath, str(file_carving_session))


def file_carving_session_archive_path(instance, filename):
    return os.path.join(file_carving_session_dir_path(instance), "archive.tar")


class FileCarvingSession(models.Model):
    id = models.UUIDField(primary_key=True)
    carve_guid = models.UUIDField(unique=True)
    serial_number = models.TextField(db_index=True)

    distributed_query = models.ForeignKey(DistributedQuery, on_delete=models.CASCADE, null=True)
    pack_query = models.ForeignKey(PackQuery, on_delete=models.CASCADE, null=True)

    paths = ArrayField(models.CharField(max_length=1024), default=list)
    carve_size = models.BigIntegerField()
    block_size = models.IntegerField()
    block_count = models.IntegerField()
    archive = models.FileField(upload_to=file_carving_session_archive_path, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.pk}_{self.serial_number}"

    def get_archive_name(self):
        return f"{self}.tar"


def file_carving_block_path(instance, filename):
    return os.path.join(file_carving_session_dir_path(instance.file_carving_session), str(instance.block_id))


class FileCarvingBlock(models.Model):
    file_carving_session = models.ForeignKey(FileCarvingSession, on_delete=models.CASCADE)
    block_id = models.IntegerField()
    file = models.FileField(upload_to=file_carving_block_path)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = (("file_carving_session", "block_id"),)
