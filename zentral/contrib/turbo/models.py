import uuid

from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, models, transaction
from django.db.models import Exists, OuterRef, Q
from django.urls import reverse

from zentral.contrib.inventory.models import BaseEnrollment, MetaMachine, Tag
from zentral.utils.backend_model import BackendInstance

from .command_backends import CommandBackend, get_command_backend, get_command_backend_class
from .compliance_checks import sync_mscp_check_compliance_check


# interval bounds shared by the cadence fields: 1 minute to 7 days
INTERVAL_MIN = 60
INTERVAL_MAX = 604800


class ConfigurationManager(models.Manager):
    def can_be_deleted(self):
        # blocked by any enrollment (Enrollment.configuration is PROTECT) or any schedule: RecurringJob /
        # OneTimeJob.configuration is CASCADE, so deleting would silently drop the schedules and their
        # per-machine ledger rows
        return self.filter(
            ~Exists(Enrollment.objects.filter(configuration=OuterRef("pk"))),
            ~Exists(RecurringJob.objects.filter(configuration=OuterRef("pk"))),
            ~Exists(OneTimeJob.objects.filter(configuration=OuterRef("pk"))),
        )

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
        d = {"pk": str(self.pk), "name": self.name}
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
        # the events of an enrollment are also on the page of its configuration
        return {"turbo_configuration": [(self.configuration_id,)]}

    def can_be_updated(self):
        return Enrollment.objects.can_be_updated().filter(pk=self.pk).exists()

    def can_be_deleted(self):
        # the manager check is complete (distributor + enrolled machine)
        return Enrollment.objects.can_be_deleted().filter(pk=self.pk).exists()


class EnrolledMachine(models.Model):
    # enrolling deletes the serial's other rows, so a machine has at most one row at any time
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    # Only sha256(token) hex is stored — unlike osquery/munki, which keep the raw token.
    token_hash = models.CharField(max_length=64, unique=True)
    last_seen_at = models.DateTimeField(null=True)   # throttled per-request heartbeat (the admin "last seen")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("enrollment", "serial_number"),)

    def __str__(self):
        return self.serial_number

    def get_urlsafe_serial_number(self):
        # a serial can contain any character (agent-supplied); encode it for the admin URLs, like
        # inventory's MachineSnapshot.urlsafe_serial_number
        return MetaMachine.make_urlsafe_serial_number(self.serial_number)


class Job(models.Model):
    # Polymorphic anchor for the things Turbo runs. One row per Script / MSCPCheck / Command (each O2Os
    # in below). The kind is the wire `kind`; Job.pk is the wire identity of the definition (the `pk` in
    # each job block). Per-machine delivery is tracked against the scheduling row, not the Job.
    class Kind(models.TextChoices):
        SCRIPT = "script", "Script"
        MSCP_CHECK = "mscp_check", "mSCP check"
        # one value per command backend, flat — never a "command" kind with a sub-type. A new command is
        # then a config change for an agent rather than a protocol change, because an agent already
        # drops a kind it does not know, element by element.
        SYSDIAGNOSE = CommandBackend.SYSDIAGNOSE.value, CommandBackend.SYSDIAGNOSE.label
        FILE_EXPORT = CommandBackend.FILE_EXPORT.value, CommandBackend.FILE_EXPORT.label

    # every relation a definition can hang off a Job. Callers that dereference job.definition prefetch
    # with it — one tuple, so a new kind cannot be forgotten at one of the many select_related sites.
    DEFINITION_RELATIONS = ("script", "mscp_check", "command")

    @classmethod
    def definition_relations(cls, prefix=""):
        # select_related() arguments for every definition relation, under an optional prefix
        # ("job__", "one_time_job__job__"): the callers reach a Job from several depths
        return tuple(f"{prefix}{relation}" for relation in cls.DEFINITION_RELATIONS)

    @classmethod
    def allowed_schedule_modes(cls, kind):
        # a command backend declares the scheduling rows its kind may be attached to — the first wave is
        # one-time only, since a recurring collection is a log shipper rather than a job. A Script or an
        # MSCPCheck is schedulable either way. Keyed on the kind, not an instance, because the callers
        # validate a choice before any row exists.
        if kind in CommandBackend.values:
            return get_command_backend_class(kind).allowed_modes
        return frozenset(ScheduleMode.values)

    @classmethod
    def kinds_for_schedule_mode(cls, mode):
        return [kind for kind in cls.Kind.values if mode in cls.allowed_schedule_modes(kind)]

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
    def is_command(self):
        return self.kind in CommandBackend.values

    @property
    def definition(self):
        # None for a kind this instance does not know — an older release reading a row a newer one wrote
        # during a rolling deploy. Callers treat that as "not deliverable" instead of dereferencing it.
        if self.kind == self.Kind.SCRIPT:
            return self.script
        elif self.kind == self.Kind.MSCP_CHECK:
            return self.mscp_check
        elif self.is_command:
            return self.command

    @property
    def definition_payload_key(self):
        # the turbo-local key the definition block rides under in an event payload
        if self.kind == self.Kind.SCRIPT:
            return "script"
        elif self.kind == self.Kind.MSCP_CHECK:
            return "mscp_check"
        elif self.is_command:
            return "command"

    def definition_linked_objects_keys(self):
        # link the definition (Script / MSCPCheck / Command) — the page an admin navigates to — not the
        # Job anchor
        return {f"turbo_{self.definition_payload_key}": [(self.definition.pk,)]}

    def definition_wire_ref(self):
        # the definition block for an event payload: (payload_key, {pk + human context}). The payload
        # key is turbo-local (script / mscp_check / command); the pk-only linked object stays namespaced
        # (turbo_script / turbo_mscp_check / turbo_command) — see events.get_linked_objects_keys.
        definition = self.definition
        key = self.definition_payload_key
        if self.kind == self.Kind.SCRIPT:
            return key, {"pk": str(definition.pk), "name": definition.name}
        elif self.kind == self.Kind.MSCP_CHECK:
            return key, {"pk": str(definition.pk), "rule_id": definition.rule_id}
        # the backend is the kind, so it is redundant on the wire ref — but a store consumer reading a
        # command result should not have to know that to tell one command from another
        return key, {"pk": str(definition.pk), "name": definition.name, "backend": definition.backend}


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
            "pk": str(self.pk),
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
        keys = {}
        if self.tag_id:
            keys["tag"] = [(self.tag_id,)]
        # a script is a compliance check only when the user asks for one
        if self.compliance_check_id:
            keys["compliance_check"] = [(self.compliance_check_id,)]
        return keys

    def delete(self, *args, **kwargs):
        compliance_check, job = self.compliance_check, self.job
        result = super().delete(*args, **kwargs)
        if compliance_check:
            compliance_check.delete()
        job.delete()  # cascades to RecurringJob / OneTimeJob and their per-machine trackers
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

    def linked_objects_keys_for_event(self):
        return {"compliance_check": [(self.compliance_check_id,)]}

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
        # the MSCPCheck has no name of its own; derive a unique CC name from its identity
        # (rule_id+baseline+ODV). The ODV is rendered with its type: odv_int=1, odv_string="1" and
        # odv_bool=True are three different identities, and the untyped form would collide on the
        # ComplianceCheck (model, name) unique constraint
        name = self.rule_id
        if self.baseline:
            name = f"{name} / {self.baseline}"
        if self.odv_int is not None:
            name = f"{name} = int({self.odv_int})"
        elif self.odv_string is not None:
            name = f"{name} = string({self.odv_string})"
        elif self.odv_bool is not None:
            name = f"{name} = bool({str(self.odv_bool).lower()})"
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
            "pk": str(self.pk),
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
        job.delete()  # cascades to RecurringJob / OneTimeJob and their per-machine trackers
        return result


class Command(BackendInstance):
    # The third definition family: verbs with a small options dict. Script and MSCPCheck each earn a
    # table because Postgres enforces their identity (FKs with DB semantics, typed ODV columns and
    # their constraints); a command has neither, and its variation is agent behaviour plus result
    # handling — Python, not schema. So one table and a backend registry, the split stores.Store and
    # probes.Action already use. A command that grows an FK or a constraint graduates to its own
    # definition model under the same Job anchor, additively.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    job = models.OneToOneField(Job, on_delete=models.CASCADE, related_name="command", editable=False)
    # IMMUTABLE once set: Job.kind mirrors it, and both are the wire identity of this definition, so
    # changing the behaviour under a stable pk and version is not an edit but a different command.
    # Enforced by the serializer — the DB column stays writable so a create can set it.
    backend = models.CharField(choices=CommandBackend.choices)
    backend_enum = CommandBackend
    # inherited from BackendInstance: name (unique), description, backend_kwargs, created_at, updated_at
    # version lives on the Job (bumped on a kwargs change); access via self.job.version

    objects = JobDefinitionManager()

    def get_backend(self, load=False):
        return get_command_backend(self, load)

    def get_absolute_url(self):
        return reverse("turbo:command", args=(self.pk,))

    @property
    def version(self):
        return self.job.version

    def save(self, *args, **kwargs):
        # atomic so a failed insert (e.g. duplicate name) rolls the auto-minted Job back, no orphan
        with transaction.atomic():
            if not self.job_id:
                self.job = Job.objects.create(kind=self.backend)
            super().save(*args, **kwargs)

    def can_be_deleted(self):
        return Command.objects.can_be_deleted().filter(pk=self.pk).exists()

    def wire_payload(self):
        # a pure function of (kwargs, version): cached for config_refresh_interval and re-served to
        # every in-scope machine, so nothing per-machine or per-run may enter it — which is why an
        # upload destination is minted on its own endpoint instead
        return self.get_backend(load=True).wire_payload()

    def serialize_for_event(self, keys_only=False):
        d = super().serialize_for_event(keys_only)
        if not keys_only:
            d["version"] = self.job.version
        return d

    def linked_objects_keys_for_event(self):
        return {}

    def delete(self, *args, **kwargs):
        job = self.job
        result = super().delete(*args, **kwargs)
        job.delete()  # cascades to RecurringJob / OneTimeJob and their per-machine trackers
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


class ScheduleMode(models.TextChoices):
    # the wire `schedule.mode`: which kind of scheduling row delivered a job to a machine
    RECURRING = "recurring", "Recurring"
    ONE_TIME = "one_time", "One-time"


class RecurringJob(JobScope):
    wire_mode = ScheduleMode.RECURRING

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
            "pk": str(self.pk),
            "configuration": self.configuration.serialize_for_event(keys_only=True),
            "job": {"pk": str(self.job_id), "kind": self.job.kind, "version": self.job.version},
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
        if self.interval is not None:
            d["interval"] = self.interval
        d.update(self.serialize_scope_for_event())
        return d

    def linked_objects_keys_for_event(self):
        keys = {"turbo_configuration": [(self.configuration_id,)]}
        keys.update(self.job.definition_linked_objects_keys())
        return keys


class OneTimeJob(JobScope):
    wire_mode = ScheduleMode.ONE_TIME
    # create / update / delete are registered by hand in pbac.py, typed on the configuration or on
    # the row. The auto-registered ones would take System with no context and could not be refused
    # per kind. Only view stays auto-registered: a typed view action would have to scope a list,
    # which means filtering a queryset by policy rather than deciding one request.
    pbac_excluded_default_permissions = ("add", "change", "delete")

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
            "pk": str(self.pk),
            "configuration": self.configuration.serialize_for_event(keys_only=True),
            "job": {"pk": str(self.job_id), "kind": self.job.kind, "version": self.job.version},
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
        keys = {"turbo_configuration": [(self.configuration_id,)]}
        keys.update(self.job.definition_linked_objects_keys())
        return keys


class OneTimeJobMachine(models.Model):
    # Per-(machine, one-time job) tracker and the REQUIRED done-gate: once last_result_at is set (by a
    # current-version result) ConfigView stops serving the job to this machine — the one-shot analogue of
    # osquery's DistributedQueryMachine. Correlation on the wire is by the OneTimeJob pk.
    one_time_job = models.ForeignKey(OneTimeJob, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)

    seen_version = models.PositiveIntegerField(null=True)          # version the agent acks holding (status)
    last_result_version = models.PositiveIntegerField(null=True)   # version of the latest run (results)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True)                 # most recent ack (set on ack, not auto_now)
    first_result_at = models.DateTimeField(null=True)
    last_result_at = models.DateTimeField(null=True)     # current-version result ⇒ done, config stops serving
    # set by the status channel when the agent stops reporting it; cleared when it reappears. cleanup purges
    # only rows whose OneTimeJob window has closed, so a live gate is never dropped.
    removed_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["one_time_job", "serial_number"],
                                    name="turbo_onetimejobmachine_unique"),
        ]

    def __str__(self):
        return f"{self.one_time_job} on {self.serial_number}"


class RecurringJobMachine(models.Model):
    # Per-(machine, recurring job) tracker: purely a record of what the agent reports (held version /
    # cadence / last run), for troubleshooting. Recurring jobs are always served, so nothing here gates
    # delivery. Correlation on the wire is by the RecurringJob pk.
    recurring_job = models.ForeignKey(RecurringJob, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)

    seen_version = models.PositiveIntegerField(null=True)
    seen_interval = models.PositiveIntegerField(null=True)         # effective cadence the agent reported
    last_result_version = models.PositiveIntegerField(null=True)

    first_seen_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(null=True)
    first_result_at = models.DateTimeField(null=True)
    last_result_at = models.DateTimeField(null=True)               # "last run" — informational
    removed_at = models.DateTimeField(null=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["recurring_job", "serial_number"],
                                    name="turbo_recurringjobmachine_unique"),
        ]

    def __str__(self):
        return f"{self.recurring_job} on {self.serial_number}"


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


def resolve_machine_schedules(configuration, serial_number, schedule_pks):
    # Batched resolver for the results / status ingest paths: maps each scheduling-row pk to its
    # per-machine tracker (RecurringJobMachine or OneTimeJobMachine) and the Job it anchors, creating any
    # missing tracker rows in bulk. Only rows of the machine's own configuration are resolved — a
    # scheduling-row pk is otherwise trusted from the wire, so without this a machine could report
    # results/status for another configuration's job. Unknown / malformed / foreign pks are simply absent
    # from the returned dict (callers skip them). The same pk repeated returns the same row instance, so
    # callers accumulate onto it across several entries in one batch.
    valid = _unique_schedule_uuids(schedule_pks)
    if not valid:
        return {}

    # the results path scores compliance from definition.compliance_check, so prefetch it here to keep
    # ingest O(1) in the batch size (no per-result SELECT to dereference the check). A command carries
    # neither a tag nor a check, so DEFINITION_RELATIONS covers it with nothing extra.
    related = (*(f"job__{relation}" for relation in Job.DEFINITION_RELATIONS),
               "job__script__tag", "job__script__compliance_check",
               "job__mscp_check__compliance_check")
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

    def recurring_rows():
        return {r.recurring_job_id: r for r in RecurringJobMachine.objects.filter(
            serial_number=serial_number, recurring_job_id__in=recurring_jobs)}

    def one_time_rows():
        return {r.one_time_job_id: r for r in OneTimeJobMachine.objects.filter(
            serial_number=serial_number, one_time_job_id__in=one_time_jobs)}

    recurring = recurring_rows()
    to_create = [RecurringJobMachine(serial_number=serial_number, recurring_job_id=pk)
                 for pk in recurring_jobs if pk not in recurring]
    if to_create:
        RecurringJobMachine.objects.bulk_create(to_create, ignore_conflicts=True)
        # re-read for the authoritative rows; also covers a rare concurrent create
        recurring = recurring_rows()

    one_time = one_time_rows()
    to_create = [OneTimeJobMachine(serial_number=serial_number, one_time_job_id=pk)
                 for pk in one_time_jobs if pk not in one_time]
    if to_create:
        OneTimeJobMachine.objects.bulk_create(to_create, ignore_conflicts=True)
        one_time = one_time_rows()

    resolved = {}
    for schedule_pk, pk in valid.items():
        rj = recurring_jobs.get(pk)
        if rj is not None:
            row = recurring.get(pk)
            if row is not None:
                resolved[schedule_pk] = (row, rj.job)
            continue
        otj = one_time_jobs.get(pk)
        if otj is not None:
            row = one_time.get(pk)
            if row is not None:
                resolved[schedule_pk] = (row, otj.job)
    return resolved
