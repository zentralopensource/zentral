import uuid

from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, models, transaction
from django.db.models import Exists, OuterRef, Q
from django.urls import reverse

from zentral.contrib.inventory.models import BaseEnrollment, Tag

from .compliance_checks import sync_mscp_check_compliance_check


# interval bounds shared by the cadence fields: 1 minute to 7 days
INTERVAL_MIN = 60
INTERVAL_MAX = 604800


class ConfigurationManager(models.Manager):
    def can_be_deleted(self):
        # blocked by any enrollment (Enrollment.configuration is PROTECT)
        return self.filter(~Exists(Enrollment.objects.filter(configuration=OuterRef("pk"))))

    def summary(self):
        # per-configuration counts for the overview; correlated subqueries so the four aggregates
        # don't fan out against each other (machines = distinct serials, an enrollment may re-enroll)
        query = (
            "select c.id as pk, c.name,"
            "(select count(*) from turbo_recurringjob where configuration_id = c.id) as recurring_job_count,"
            "(select count(*) from turbo_onetimejob where configuration_id = c.id) as one_time_job_count,"
            "(select count(*) from turbo_enrollment where configuration_id = c.id) as enrollment_count,"
            "(select count(distinct m.serial_number) from turbo_enrolledmachine as m"
            " join turbo_enrollment as e on (m.enrollment_id = e.id)"
            " where e.configuration_id = c.id) as machine_count "
            "from turbo_configuration as c "
            "order by c.name, c.created_at"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [col.name for col in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


class Configuration(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)

    collect_inventory = models.BooleanField(
        default=True,
        help_text="When enabled, the agent posts a full machine inventory snapshot on the interval below"
    )
    inventory_interval = models.IntegerField(
        default=86400,  # 1d
        validators=[MinValueValidator(INTERVAL_MIN), MaxValueValidator(INTERVAL_MAX)],
        help_text="Inventory refresh interval in seconds (Minimum: 60s)"
    )
    default_check_interval = models.IntegerField(
        default=86400,  # 1d
        validators=[MinValueValidator(INTERVAL_MIN), MaxValueValidator(INTERVAL_MAX)],
        help_text="Default run interval in seconds for recurring jobs that don't set their own"
    )
    config_refresh_interval = models.IntegerField(
        default=600,  # 10m
        validators=[MinValueValidator(INTERVAL_MIN), MaxValueValidator(INTERVAL_MAX)],
        help_text="How long the agent may trust a cached configuration before refreshing it, in seconds"
    )
    results_batch_size = models.IntegerField(
        default=100,
        validators=[MinValueValidator(1), MaxValueValidator(1000)],
        help_text="Maximum number of results the agent uploads per request; a larger backlog is drained "
                  "over several requests"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("turbo:configuration", args=(self.pk,))

    objects = ConfigurationManager()

    def can_be_deleted(self):
        return Configuration.objects.can_be_deleted().filter(pk=self.pk).exists()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "description": self.description,
            "collect_inventory": self.collect_inventory,
            "inventory_interval": self.inventory_interval,
            "default_check_interval": self.default_check_interval,
            "config_refresh_interval": self.config_refresh_interval,
            "results_batch_size": self.results_batch_size,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        })
        return d


class EnrollmentManager(models.Manager):
    def can_be_updated(self):
        # a distributor-owned enrollment is managed by that distributor, not edited (e.g. version bump) here
        return self.filter(distributor_content_type__isnull=True, distributor_pk__isnull=True)

    def can_be_deleted(self):
        # updatable AND not blocked by any enrolled machine
        return self.can_be_updated().filter(
            ~Exists(EnrolledMachine.objects.filter(enrollment=OuterRef("pk"))))


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.PROTECT)

    objects = EnrollmentManager()

    def get_absolute_url(self):
        return f"{self.configuration.get_absolute_url()}#enrollment-{self.pk}"

    def get_description_for_distributor(self):
        return f"Turbo configuration: {self.configuration}"

    def serialize_for_event(self, keys_only=False):
        if keys_only:
            return {"pk": self.pk}
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = self.configuration.serialize_for_event(keys_only=True)
        return enrollment_dict

    def linked_objects_keys_for_event(self):
        # link both the enrollment and its configuration, so enrollment audit events surface under the config too
        return {
            "turbo_enrollment": [(self.pk,)],
            "turbo_configuration": [(self.configuration_id,)],
        }

    def can_be_updated(self):
        return Enrollment.objects.can_be_updated().filter(pk=self.pk).exists()

    def can_be_deleted(self):
        # the manager check is complete (distributor + enrolled machine)
        return Enrollment.objects.can_be_deleted().filter(pk=self.pk).exists()


class EnrolledMachineManager(models.Manager):
    # a serial re-enrolling into another configuration leaves stale rows behind, so its current
    # enrollment is always the most recent one.
    def latest_per_serial(self):
        latest = (
            self.order_by("serial_number", "-created_at")
            .distinct("serial_number")
            .values_list("pk", flat=True)
        )
        return self.filter(pk__in=latest).select_related("enrollment__configuration")

    def latest_for_serial_number(self, serial_number):
        return (
            self.filter(serial_number=serial_number)
            .select_related("enrollment__configuration")
            .order_by("-created_at")
            .first()
        )


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    # Only sha256(token) hex is stored — unlike osquery/munki, which keep the raw token.
    token_hash = models.CharField(max_length=64, unique=True)
    last_seen_at = models.DateTimeField(null=True)   # throttled per-request heartbeat (the admin "last seen")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrolledMachineManager()

    class Meta:
        unique_together = (("enrollment", "serial_number"),)

    def __str__(self):
        return self.serial_number


class Job(models.Model):
    # Polymorphic anchor for the things Turbo runs. One row per Script / MSCPCheck (each O2Os in below).
    # The kind is the wire `kind`; Job.pk is the wire identity and the key MachineJobStatus tracks against.
    class Kind(models.TextChoices):
        SCRIPT = "script", "Script"
        MSCP_CHECK = "mscp_check", "mSCP check"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    kind = models.CharField(max_length=32, choices=Kind.choices, editable=False)
    # wire version; bumped whenever the Script / MSCPCheck definition changes. The agent re-runs a job
    # whose version moved, and results are only scored/tagged when their version matches the current one.
    version = models.PositiveIntegerField(default=1, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.get_kind_display()} job {self.pk}"

    def bump_version(self):
        self.version = models.F("version") + 1
        self.save()
        self.refresh_from_db()

    @property
    def definition(self):
        if self.kind == self.Kind.SCRIPT:
            return self.script
        elif self.kind == self.Kind.MSCP_CHECK:
            return self.mscp_check

    def definition_linked_objects_keys(self):
        # link the definition (Script / MSCPCheck) — the page an admin navigates to — not the Job anchor
        key = "turbo_script" if self.kind == self.Kind.SCRIPT else "turbo_mscp_check"
        return {key: [(self.definition.pk,)]}


class JobDefinitionManager(models.Manager):
    # Script / MSCPCheck: deletable only while no schedule (RecurringJob / OneTimeJob) references its Job
    def can_be_deleted(self):
        return self.filter(
            ~Exists(RecurringJob.objects.filter(job=OuterRef("job_id"))),
            ~Exists(OneTimeJob.objects.filter(job=OuterRef("job_id"))),
        )


class Script(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(Job, on_delete=models.CASCADE, related_name="script", editable=False)
    name = models.CharField(max_length=256, unique=True)
    description = models.TextField(blank=True)
    source = models.TextField(help_text="zsh script; exit 0 = OK, exit > 0 = FAIL")
    # version lives on the Job (bumped on definition change); access via self.job.version

    # compliance role: when set, the script is a compliance check (ComplianceCheck model="TurboScript")
    compliance_check = models.OneToOneField(
        "compliance_checks.ComplianceCheck",
        on_delete=models.SET_NULL,
        related_name="turbo_script",
        editable=False,
        null=True,
    )
    # tagging role: add this tag on exit 0, remove it on exit > 0 (couldn't run = no-op)
    tag = models.ForeignKey(Tag, on_delete=models.SET_NULL, related_name="+", blank=True, null=True,
                            help_text="Added on exit 0, removed on exit > 0")

    # COMPATIBILITY only ("can it run here") — WHERE it runs (scope) lives on the scheduling layer.
    arch_amd64 = models.BooleanField(verbose_name="Run on Intel architecture", default=True)
    arch_arm64 = models.BooleanField(verbose_name="Run on Apple Silicon architecture", default=True)
    min_os_version = models.CharField(max_length=32, blank=True)
    max_os_version = models.CharField(max_length=32, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("turbo:script", args=(self.pk,))

    @property
    def version(self):
        return self.job.version

    def save(self, *args, **kwargs):
        # atomic so a failed insert (e.g. duplicate name) rolls the auto-minted Job back, no orphan
        with transaction.atomic():
            if not self.job_id:
                self.job = Job.objects.create(kind=Job.Kind.SCRIPT)
            super().save(*args, **kwargs)

    def compliance_check_enabled(self):
        # compliance_check_id (the FK column) avoids a query to dereference the related object
        return self.compliance_check_id is not None

    objects = JobDefinitionManager()

    def can_be_deleted(self):
        return Script.objects.can_be_deleted().filter(pk=self.pk).exists()

    def wire_payload(self):
        # tagging is applied server-side from the reported exit code, so it's not in the payload; the
        # arch/OS compatibility gate is applied by the agent, so those fields ride along
        return {
            "source": self.source,
            "compliance": self.compliance_check_id is not None,
            "arch_amd64": self.arch_amd64,
            "arch_arm64": self.arch_arm64,
            "min_os_version": self.min_os_version,
            "max_os_version": self.max_os_version,
        }

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "name": self.name,
            "source": self.source,
            "version": self.job.version,
            "arch_amd64": self.arch_amd64,
            "arch_arm64": self.arch_arm64,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if self.description:
            d["description"] = self.description
        if self.min_os_version:
            d["min_os_version"] = self.min_os_version
        if self.max_os_version:
            d["max_os_version"] = self.max_os_version
        if self.compliance_check:
            d["compliance_check"] = self.compliance_check.serialize_for_event()
        if self.tag:
            d["tag"] = self.tag.serialize_for_event(keys_only=True)
        return d

    def linked_objects_keys_for_event(self):
        keys = {"turbo_script": [(self.pk,)]}
        if self.tag_id:
            keys["tag"] = [(self.tag_id,)]
        return keys

    def delete(self, *args, **kwargs):
        compliance_check, job = self.compliance_check, self.job
        result = super().delete(*args, **kwargs)
        if compliance_check:
            compliance_check.delete()
        job.delete()  # cascades to RecurringJob / OneTimeJob / MachineJobStatus
        return result


class MSCPCheck(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(Job, on_delete=models.CASCADE, related_name="mscp_check", editable=False)
    compliance_check = models.OneToOneField(
        "compliance_checks.ComplianceCheck",
        on_delete=models.CASCADE,
        related_name="turbo_mscp_check",
        editable=False,
    )
    rule_id = models.TextField()
    baseline = models.CharField(
        max_length=64, blank=True,
        help_text="mSCP baseline key (e.g. cis_lvl1, stig); the agent uses that baseline's default ODV for "
                  "the rule. Mutually exclusive with an explicit ODV override below."
    )
    # ODV (Organization Defined Value): an mSCP rule has AT MOST ONE, in one of three typed columns.
    # `baseline` and an explicit ODV are MUTUALLY EXCLUSIVE (see the CheckConstraint): a check either tracks
    # a baseline's default ODV, pins a fixed ODV, or sets neither (⇒ the agent's recommended default for the
    # rule). The check/fix logic and the baseline defaults are bundled & signed in the agent, not here.
    odv_int = models.IntegerField(null=True, blank=True)
    odv_string = models.TextField(null=True, blank=True)
    odv_bool = models.BooleanField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(Q(odv_int__isnull=True, odv_string__isnull=True)
                       | Q(odv_int__isnull=True, odv_bool__isnull=True)
                       | Q(odv_string__isnull=True, odv_bool__isnull=True)),
                name="turbo_mscpcheck_at_most_one_odv",
            ),
            models.CheckConstraint(
                # baseline and an explicit ODV are mutually exclusive: blank baseline OR no ODV set
                check=(Q(baseline="")
                       | Q(odv_int__isnull=True, odv_string__isnull=True, odv_bool__isnull=True)),
                name="turbo_mscpcheck_baseline_xor_odv",
            ),
            models.UniqueConstraint(
                fields=["rule_id", "baseline", "odv_int", "odv_string", "odv_bool"],
                name="turbo_mscpcheck_unique_rule_baseline_odv",
                nulls_distinct=False,  # so two "same rule_id + baseline, no-ODV" rows collide
            ),
        ]

    def __str__(self):
        return self.rule_id

    def get_absolute_url(self):
        return reverse("turbo:mscp_check", args=(self.pk,))

    @property
    def version(self):
        return self.job.version

    @property
    def odv(self):
        # the single ODV override value, whichever typed column is set (None = no override, defer to baseline)
        for value in (self.odv_int, self.odv_string, self.odv_bool):
            if value is not None:
                return value
        return None

    @property
    def compliance_check_name(self):
        # the MSCPCheck has no name of its own; derive a unique CC name from its identity (rule_id+baseline+ODV)
        name = self.rule_id
        if self.baseline:
            name = f"{name} / {self.baseline}"
        if self.odv is not None:
            name = f"{name} = {self.odv}"
        return name

    def save(self, *args, **kwargs):
        # atomic so a failed insert (constraint violation) rolls the auto-minted Job + ComplianceCheck
        # back together, leaving no orphan Job/ComplianceCheck behind
        with transaction.atomic():
            if not self.job_id:
                self.job = Job.objects.create(kind=Job.Kind.MSCP_CHECK)
            if not self.compliance_check_id:
                sync_mscp_check_compliance_check(self)  # mints the compliance check
            super().save(*args, **kwargs)

    def wire_payload(self):
        # baseline XOR odv (enforced): the agent uses the baseline's default, the pinned value, or—when
        # neither is set—its own recommended default for the rule
        payload = {"rule_id": self.rule_id}
        if self.baseline:
            payload["baseline"] = self.baseline
        if self.odv_int is not None:
            payload["odv_int"] = self.odv_int
        elif self.odv_string is not None:
            payload["odv_string"] = self.odv_string
        elif self.odv_bool is not None:
            payload["odv_bool"] = self.odv_bool
        return payload

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "rule_id": self.rule_id,
            "version": self.job.version,
            "compliance_check": self.compliance_check.serialize_for_event(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if self.baseline:
            d["baseline"] = self.baseline
        if self.odv_int is not None:
            d["odv_int"] = self.odv_int
        if self.odv_string is not None:
            d["odv_string"] = self.odv_string
        if self.odv_bool is not None:
            d["odv_bool"] = self.odv_bool
        return d

    objects = JobDefinitionManager()

    def can_be_deleted(self):
        return MSCPCheck.objects.can_be_deleted().filter(pk=self.pk).exists()

    def delete(self, *args, **kwargs):
        compliance_check, job = self.compliance_check, self.job
        result = super().delete(*args, **kwargs)
        compliance_check.delete()
        job.delete()  # cascades to RecurringJob / OneTimeJob / MachineJobStatus
        return result


class JobScope(models.Model):
    # Shared by the scheduling models: WHICH configuration + machines a job is delivered to.
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    tags = models.ManyToManyField(Tag, blank=True, related_name="%(app_label)s_%(class)s_tags")
    excluded_tags = models.ManyToManyField(Tag, blank=True, related_name="%(app_label)s_%(class)s_excluded_tags")
    serial_numbers = ArrayField(models.TextField(), blank=True, default=list)
    excluded_serial_numbers = ArrayField(models.TextField(), blank=True, default=list)

    class Meta:
        abstract = True

    @classmethod
    def in_scope(cls, configuration, serial_number, tag_ids):
        # one SQL query: in scope iff (no tags AND no serials -> all machines in the config) OR a tag
        # matches OR the serial is listed; excluded_tags / excluded_serial_numbers always win. Tag tests
        # use EXISTS on the M2M through-tables (no join explosion); serials use Postgres array containment.
        fk = cls._meta.model_name
        tags_through = cls.tags.through
        excluded_tags_through = cls.excluded_tags.through
        has_any_tag = Exists(tags_through.objects.filter(**{fk: OuterRef("pk")}))
        tag_match = Exists(tags_through.objects.filter(**{fk: OuterRef("pk"), "tag_id__in": tag_ids}))
        excluded_tag_match = Exists(
            excluded_tags_through.objects.filter(**{fk: OuterRef("pk"), "tag_id__in": tag_ids}))
        return (
            cls.objects
            .filter(configuration=configuration)
            .annotate(_has_any_tag=has_any_tag, _tag_match=tag_match, _excluded_tag_match=excluded_tag_match)
            .filter(Q(_has_any_tag=False, serial_numbers=[])
                    | Q(_tag_match=True)
                    | Q(serial_numbers__contains=[serial_number]))
            .exclude(Q(_excluded_tag_match=True) | Q(excluded_serial_numbers__contains=[serial_number]))
        )

    def serialize_scope_for_event(self):
        d = {}
        tags = [t.serialize_for_event(keys_only=True) for t in self.tags.all()]
        if tags:
            d["tags"] = tags
        excluded_tags = [t.serialize_for_event(keys_only=True) for t in self.excluded_tags.all()]
        if excluded_tags:
            d["excluded_tags"] = excluded_tags
        if self.serial_numbers:
            d["serial_numbers"] = self.serial_numbers
        if self.excluded_serial_numbers:
            d["excluded_serial_numbers"] = self.excluded_serial_numbers
        return d


class RecurringJob(JobScope):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    interval = models.IntegerField(
        null=True, blank=True,
        validators=[MinValueValidator(INTERVAL_MIN), MaxValueValidator(INTERVAL_MAX)],
        help_text="Run interval in seconds; leave empty to use the configuration default"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["configuration", "job"], name="turbo_recurringjob_unique_config_job"),
        ]

    def __str__(self):
        return f"{self.job} in {self.configuration}"

    def get_absolute_url(self):
        # no detail page of its own; managed on the configuration page
        return f"{self.configuration.get_absolute_url()}#recurring-job-{self.pk}"

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "configuration": self.configuration.serialize_for_event(keys_only=True),
            "job": {"pk": self.job_id, "kind": self.job.kind, "version": self.job.version},
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if self.interval is not None:
            d["interval"] = self.interval
        d.update(self.serialize_scope_for_event())
        return d

    def linked_objects_keys_for_event(self):
        keys = {
            "turbo_recurring_job": [(self.pk,)],
            "turbo_configuration": [(self.configuration_id,)],
        }
        keys.update(self.job.definition_linked_objects_keys())
        return keys


class OneTimeJob(JobScope):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    not_before = models.DateTimeField(null=True, blank=True)   # don't deliver before this (schedule in the future)
    not_after = models.DateTimeField(null=True, blank=True)    # delivery window end / expiry
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                check=(Q(not_before__isnull=True) | Q(not_after__isnull=True)
                       | Q(not_before__lte=models.F("not_after"))),
                name="turbo_onetimejob_not_before_lte_not_after",
            ),
        ]

    def __str__(self):
        return f"one-time {self.job}"

    def get_absolute_url(self):
        # no detail page of its own; managed on the configuration page
        return f"{self.configuration.get_absolute_url()}#one-time-job-{self.pk}"

    def serialize_for_event(self):
        d = {
            "pk": self.pk,
            "configuration": self.configuration.serialize_for_event(keys_only=True),
            "job": {"pk": self.job_id, "kind": self.job.kind, "version": self.job.version},
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if self.not_before is not None:
            d["not_before"] = self.not_before.isoformat()
        if self.not_after is not None:
            d["not_after"] = self.not_after.isoformat()
        d.update(self.serialize_scope_for_event())
        return d

    def linked_objects_keys_for_event(self):
        keys = {
            "turbo_one_time_job": [(self.pk,)],
            "turbo_configuration": [(self.configuration_id,)],
        }
        keys.update(self.job.definition_linked_objects_keys())
        return keys


class MachineJobStatusManager(models.Manager):
    @staticmethod
    def _unique_schedule_uuids(schedule_pks):
        # ordered {original value: UUID} for the well-formed, non-empty, de-duplicated pks
        parsed = {}
        for value in schedule_pks:
            if not value or value in parsed:
                continue
            try:
                parsed[value] = uuid.UUID(str(value))
            except (ValueError, TypeError):
                continue
        return parsed

    def _fetch_ledger(self, serial_number, recurring_job_ids, one_time_ids):
        ledger = {}
        for mjs in self.filter(serial_number=serial_number).filter(
                Q(one_time_job__isnull=True, job_id__in=recurring_job_ids)
                | Q(one_time_job_id__in=one_time_ids)):
            key = ("one_time", mjs.one_time_job_id) if mjs.one_time_job_id else ("recurring", mjs.job_id)
            ledger[key] = mjs
        return ledger

    def resolve_schedules(self, configuration, serial_number, schedule_pks):
        # Batched resolver for the results / status ingest paths: maps each scheduling-row pk
        # (RecurringJob = recurring, OneTimeJob = once) to its per-machine (MachineJobStatus, Job),
        # creating any missing ledger rows in bulk. Only rows of the machine's own configuration are
        # resolved — a scheduling-row pk is otherwise trusted from the wire, so without this a machine
        # could report results/status for another configuration's job. Unknown / malformed / foreign
        # pks are simply absent from the returned dict (callers skip them). The same pk repeated returns
        # the same row instance, so callers accumulate onto it across several entries in one batch.
        valid = self._unique_schedule_uuids(schedule_pks)
        if not valid:
            return {}

        # the results path scores compliance from definition.compliance_check, so prefetch it here to
        # keep ingest O(1) in the batch size (no per-result SELECT to dereference the check)
        related = ("job__script__tag", "job__script__compliance_check",
                   "job__mscp_check", "job__mscp_check__compliance_check")
        pks = list(valid.values())
        recurring_jobs = {
            rj.pk: rj
            for rj in RecurringJob.objects.select_related(*related).filter(
                pk__in=pks, configuration=configuration)
        }
        remaining = [pk for pk in pks if pk not in recurring_jobs]
        one_time_jobs = {
            otj.pk: otj
            for otj in OneTimeJob.objects.select_related(*related).filter(
                pk__in=remaining, configuration=configuration)
        } if remaining else {}
        if not recurring_jobs and not one_time_jobs:
            return {}

        recurring_job_ids = {rj.job_id for rj in recurring_jobs.values()}
        one_time_ids = set(one_time_jobs)

        ledger = self._fetch_ledger(serial_number, recurring_job_ids, one_time_ids)
        to_create = [
            self.model(serial_number=serial_number, job_id=job_id, one_time_job=None)
            for job_id in recurring_job_ids if ("recurring", job_id) not in ledger
        ] + [
            self.model(serial_number=serial_number, job_id=otj.job_id, one_time_job_id=otj.pk)
            for otj in one_time_jobs.values() if ("one_time", otj.pk) not in ledger
        ]
        if to_create:
            self.bulk_create(to_create, ignore_conflicts=True)
            # re-read for the authoritative rows; also covers a rare concurrent create
            ledger = self._fetch_ledger(serial_number, recurring_job_ids, one_time_ids)

        resolved = {}
        for schedule_pk, pk in valid.items():
            rj = recurring_jobs.get(pk)
            if rj is not None:
                mjs = ledger.get(("recurring", rj.job_id))
                if mjs is not None:
                    resolved[schedule_pk] = (mjs, rj.job)
                continue
            otj = one_time_jobs.get(pk)
            if otj is not None:
                mjs = ledger.get(("one_time", otj.pk))
                if mjs is not None:
                    resolved[schedule_pk] = (mjs, otj.job)
        return resolved


class MachineJobStatus(models.Model):
    # Per-(machine, job) ledger: what the agent has SEEN — NOT per-result (results are events / MachineStatus).
    # One row per recurring (machine, job); one row per (machine, one-time job). Correlation on the wire is
    # by scheduling-row pk (RecurringJob / OneTimeJob), so there is no per-job token.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    serial_number = models.TextField(db_index=True)
    job = models.ForeignKey(Job, on_delete=models.CASCADE)
    one_time_job = models.ForeignKey(OneTimeJob, on_delete=models.CASCADE, null=True, blank=True)

    seen_version = models.PositiveIntegerField(null=True)    # job version the agent acked holding
    seen_interval = models.PositiveIntegerField(null=True)   # effective cadence the agent reported (recurring)
    result_version = models.PositiveIntegerField(null=True)  # version that produced the last result

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True)           # most recent ack (set on ack, not auto_now)
    first_result_at = models.DateTimeField(null=True)
    # recurring: "last run". one-time: set ⇒ done, server stops serving it (no separate completed_at)
    last_result_at = models.DateTimeField(null=True)
    # set by the status channel when the agent stops reporting this job; cleared when it reappears.
    # the cleanup command purges rows removed long enough ago (sparing live one-time gates).
    removed_at = models.DateTimeField(null=True)

    objects = MachineJobStatusManager()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["serial_number", "job"],
                                    condition=Q(one_time_job__isnull=True),
                                    name="turbo_mjs_unique_recurring"),
            models.UniqueConstraint(fields=["serial_number", "one_time_job"],
                                    condition=Q(one_time_job__isnull=False),
                                    name="turbo_mjs_unique_onetime"),
        ]

    def __str__(self):
        return f"{self.job} on {self.serial_number}"
