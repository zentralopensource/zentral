from collections import namedtuple
from dateutil import parser
import json
import logging
from django.core.validators import MaxValueValidator, MinLengthValidator, MinValueValidator
from django.contrib.postgres.fields import ArrayField
from django.db import connection, models
from django.db.models import Count, Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from zentral.core.incidents.models import Severity
from zentral.contrib.inventory.models import BaseEnrollment, Certificate, File, Tag
from zentral.utils.text import shard


logger = logging.getLogger("zentral.contrib.santa.models")


# Configuration / Enrollment


class ConfigurationManager(models.Manager):
    def summary(self):
        query = (
            "select c.id as pk, c.name, c.created_at,"
            "(select count(*) from santa_enrollment where configuration_id = c.id) as enrollment_count,"
            "(select count(*) from santa_enrolledmachine as m "
            " join santa_enrollment as e on (m.enrollment_id = e.id) "
            " where e.configuration_id = c.id) as machine_count,"
            "(select count(*) from santa_rule where configuration_id = c.id) as rule_count "
            "from santa_configuration as c "
            "order by c.name, c.created_at"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        columns = [c.name for c in cursor.description]
        return [dict(zip(columns, row)) for row in cursor.fetchall()]


class Configuration(models.Model):
    MONITOR_MODE = 1
    LOCKDOWN_MODE = 2
    CLIENT_MODE_CHOICES = (
        (MONITOR_MODE, "Monitor"),
        (LOCKDOWN_MODE, "Lockdown"),
    )
    PREFLIGHT_MONITOR_MODE = "MONITOR"
    PREFLIGHT_LOCKDOWN_MODE = "LOCKDOWN"
    DEFAULT_BATCH_SIZE = 50
    DEFAULT_FULL_SYNC_INTERVAL = 600
    SYNC_SERVER_CONFIGURATION_ATTRIBUTES = {
        # 'client_mode', has to be translated to a string value
        # 'clean_sync' managed dynamically
        'batch_size',
        # 'upload_logs_url' not used
        'allowed_path_regex',
        'blocked_path_regex',
        'full_sync_interval',
        # 'fcm_token' cannot be used
        # 'fcm_full_sync_interval' cannot be used
        # 'fcm_global_rule_sync_deadline' cannot be used
        'enable_bundles',
        'enable_transitive_rules',
        # 'enable_all_event_upload' sharded
        'block_usb_mount',
        'remount_usb_mode',
    }

    name = models.CharField(max_length=256, unique=True)

    client_mode = models.IntegerField(choices=CLIENT_MODE_CHOICES, default=MONITOR_MODE)

    client_certificate_auth = models.BooleanField(
        "Client certificate authentication",
        default=False,
        help_text="If set, a client certificate will be required for sync authentication. "
                  "Santa will automatically look for a matching certificate "
                  "and its private key in the System keychain, "
                  "if the TLS server advertises the accepted CA certificates. "
                  "If the CA certificates are not sent to the client, "
                  "use the Client Auth Certificate Issuer CN setting in the configuration profile."
    )
    batch_size = models.IntegerField(
        default=DEFAULT_BATCH_SIZE,
        validators=[MinValueValidator(5), MaxValueValidator(100)],
        help_text="The number of rules to download or events to upload per request. "
                  "Multiple requests will be made if there is more work than can fit in single request."
    )
    full_sync_interval = models.IntegerField(
        default=DEFAULT_FULL_SYNC_INTERVAL,
        validators=[MinValueValidator(60), MaxValueValidator(86400)],
        help_text="The max time to wait in seconds before performing a full sync with the server. "
                  "Minimum: 60s, hardcoded in Santa."
    )
    enable_bundles = models.BooleanField(
        default=False,
        help_text="If set, the bundle scanning feature is enabled."
    )
    enable_transitive_rules = models.BooleanField(
        default=False,
        help_text="If set, the transitive rule feature is enabled."
    )

    # Paths regular expressions

    allowed_path_regex = models.TextField(
        blank=True,
        help_text="Matching binaries will be allowed to run, in both modes."
                  "Events will be logged with the 'ALLOW_SCOPE' decision."
    )
    blocked_path_regex = models.TextField(
        blank=True,
        help_text="In Monitor mode, executables whose paths are matched by this regex will be blocked."
    )

    # USB

    block_usb_mount = models.BooleanField(
        default=False,
        help_text="If set, USB mass storage devices will be blocked or remounted.",
        verbose_name="Block USB mount",
    )
    remount_usb_mode = ArrayField(
        models.CharField(max_length=16, validators=[MinLengthValidator(2)]),
        blank=True,
        default=list,
        help_text="Comma separated list of mount options used to remount the USB mass storage devices. "
                  "If left empty, the devices will not be remounted. "
                  "Only available if Block USB Mount is set.",
        verbose_name="Remount USB mode",
    )

    # Zentral options

    allow_unknown_shard = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=100,
        help_text="Restrict the reporting of 'Allow Unknown' events to a percentage (0-100) of hosts"
    )
    enable_all_event_upload_shard = models.IntegerField(
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        default=0,
        help_text="Restrict the upload of all execution events to Zentral, including those that were "
                  "explicitly allowed, to a percentage (0-100) of hosts"
    )
    sync_incident_severity = models.IntegerField(
        choices=Severity.choices(include_none=True), default=Severity.NONE.value,
        help_text="If not 'None', incidents will be automatically opened and closed when the santa agent "
                  "rules are out of sync."
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = ConfigurationManager()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("santa:configuration", args=(self.pk,))

    def get_sync_incident_severity(self):
        try:
            return Severity(self.sync_incident_severity)
        except ValueError:
            return

    def get_preflight_client_mode(self):
        if self.client_mode == self.MONITOR_MODE:
            return self.PREFLIGHT_MONITOR_MODE
        elif self.client_mode == self.LOCKDOWN_MODE:
            return self.PREFLIGHT_LOCKDOWN_MODE
        else:
            raise ValueError(f"Unknown santa client mode: {self.client_mode}")

    def is_monitor_mode(self):
        return self.client_mode == self.MONITOR_MODE

    def get_sync_server_config(self, serial_number, comparable_santa_version):
        config = {k: getattr(self, k)
                  for k in self.SYNC_SERVER_CONFIGURATION_ATTRIBUTES}

        # translate client mode
        config['client_mode'] = self.get_preflight_client_mode()

        # provide non matching regexp if the regexp are empty
        for attr in ("allowed_path_regex",
                     "blocked_path_regex"):
            if not config.get(attr):
                config[attr] = "NON_MATCHING_PLACEHOLDER_{}".format(get_random_string(8))

        # enable_all_event_upload
        config["enable_all_event_upload"] = (
            self.enable_all_event_upload_shard > 0 and
            (self.enable_all_event_upload_shard == 100 or
             shard(serial_number, self.pk) <= self.enable_all_event_upload_shard)
        )

        return config

    def get_local_config(self):
        config = {
            "ClientMode": self.client_mode,
        }
        if self.allowed_path_regex:
            config["AllowedPathRegex"] = self.allowed_path_regex
        if self.blocked_path_regex:
            config["BlockedPathRegex"] = self.blocked_path_regex
        return config

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()

    def serialize_for_event(self, keys_only=False):
        d = {"pk": self.pk, "name": self.name}
        if keys_only:
            return d
        d.update({
            "client_mode": self.get_client_mode_display(),
            "client_certificate_auth": self.client_certificate_auth,
            "batch_size": self.batch_size,
            "full_sync_interval": self.full_sync_interval,
            "enable_bundles": self.enable_bundles,
            "enable_transitive_rules": self.enable_transitive_rules,
            "allowed_path_regex": self.allowed_path_regex,
            "blocked_path_regex": self.blocked_path_regex,
            "block_usb_mount": self.block_usb_mount,
            "remount_usb_mode": self.remount_usb_mode,
            "allow_unknown_shard": self.allow_unknown_shard,
            "enable_all_event_upload_shard": self.enable_all_event_upload_shard,
            "sync_incident_severity": self.sync_incident_severity,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        })
        return d

    def can_be_deleted(self):
        return self.enrollment_set.all().count() == 0


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    def get_description_for_distributor(self):
        return "Santa configuration: {}".format(self.configuration)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = self.configuration.serialize_for_event(keys_only=True)
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("santa:configuration", args=(self.configuration.pk,)), self.pk)


class EnrolledMachineManager(models.Manager):
    def get_for_serial_number(self, serial_number):
        return list(
            self.select_related("enrollment__configuration")
            .filter(serial_number=serial_number)
            .order_by("-updated_at")
        )


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)

    hardware_uuid = models.UUIDField()  # DB index?
    serial_number = models.TextField(db_index=True)

    primary_user = models.TextField(null=True)
    client_mode = models.IntegerField(choices=Configuration.CLIENT_MODE_CHOICES)
    santa_version = models.TextField()

    binary_rule_count = models.IntegerField(null=True)
    cdhash_rule_count = models.IntegerField(null=True)
    certificate_rule_count = models.IntegerField(null=True)
    compiler_rule_count = models.IntegerField(null=True)
    signingid_rule_count = models.IntegerField(null=True)
    transitive_rule_count = models.IntegerField(null=True)
    teamid_rule_count = models.IntegerField(null=True)
    last_sync_ok = models.BooleanField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrolledMachineManager()

    class Meta:
        unique_together = ("enrollment", "hardware_uuid")

    def get_comparable_santa_version(self):
        try:
            return tuple(int(i) for i in self.santa_version.split("."))
        except ValueError:
            return ()

    def sync_ok(self):
        """
        Compare the synced and reported rules
        """
        synced_rules = {
            r["target__type"]: r["count"]
            for r in self.machinerule_set.filter(cursor__isnull=True)
                                         .values("target__type")
                                         .annotate(count=Count("id"))
        }
        ok = True
        for target_type, attr in ((Target.BINARY, "binary_rule_count"),
                                  (Target.CERTIFICATE, "certificate_rule_count"),
                                  (Target.SIGNING_ID, "signingid_rule_count"),
                                  (Target.TEAM_ID, "teamid_rule_count")):
            synced_count = synced_rules.get(target_type, 0)
            reported_count = getattr(self, attr) or 0
            if synced_count != reported_count:
                logger.error(
                    "Enrolled machine %s: %s rules synced %s, reported %s",
                    self.pk, target_type, synced_count, reported_count  # lgtm[py/clear-text-logging-sensitive-data]
                )
                ok = False
        return ok


# Rules


class TargetManager(models.Manager):
    def summary(self):
        query = (
            "with collected_files as ("
            "  select f.cdhash, f.sha_256, f.signed_by_id, f.signing_id, f.name"
            "  from inventory_file as f"
            "  join inventory_source as s on (f.source_id = s.id)"
            "  where s.module = 'zentral.contrib.santa' and s.name = 'Santa events'"
            "  group by f.cdhash, f.sha_256, f.signed_by_id, f.signing_id, f.name"
            "), collected_certificates as ("
            "  select c.sha_256, c.common_name"
            "  from inventory_certificate as c"
            "  join collected_files as f on (c.id = f.signed_by_id)"
            "  group by c.sha_256, c.common_name"
            "), collected_team_ids as ("
            "  select c.organizational_unit, c.organization"
            "  from inventory_certificate as c"
            "  join collected_files as f on (c.id = f.signed_by_id)"
            "  where c.organizational_unit ~ '[A-Z0-9]{10}'"
            "  group by c.organizational_unit, c.organization"
            ") "
            "select 'cdhash' as target_type,"
            "count(distinct cdhash) as target_count,"
            "(select count(distinct t.id)"
            " from santa_target as t"
            " join collected_files as f on (t.type = 'CDHASH' and t.identifier=f.cdhash)"
            " join santa_rule as r on (t.id = r.target_id)) as rule_count "
            "from collected_files "
            "where cdhash is not null "
            "union "
            "select 'binary' as target_type,"
            "count(*) as target_count,"
            "(select count(distinct t.id)"
            " from santa_target as t"
            " join collected_files as f on (t.type = 'BINARY' and t.identifier=f.sha_256)"
            " join santa_rule as r on (t.id = r.target_id)) as rule_count "
            "from collected_files "
            "union "
            "select 'certificate' as target_type,"
            "count(*) as target_count,"
            "(select count(distinct t.id)"
            " from santa_target as t"
            " join collected_certificates as c on (t.type = 'CERTIFICATE' and t.identifier=c.sha_256)"
            " join santa_rule as r on (t.id = r.target_id)) as rule_count "
            "from collected_certificates "
            "union "
            "select 'teamid' as target_type,"
            "count(*) as target_count,"
            "(select count(distinct t.id)"
            " from santa_target as t"
            " join collected_team_ids as i on (t.type = 'TEAMID' and t.identifier=i.organizational_unit)"
            " join santa_rule as r on (t.id = r.target_id)) as rule_count "
            "from collected_team_ids "
            "union "
            "select 'signingid' as target_type,"
            "count(distinct signing_id) as target_count,"
            "(select count(distinct t.id)"
            " from santa_target as t"
            " join collected_files as f on (t.type = 'SIGNINGID' and t.identifier=f.signing_id)"
            " join santa_rule as r on (t.id = r.target_id)) as rule_count "
            "from collected_files "
            "where signing_id is not null "
            "union "
            "select 'bundle' as target_type,"
            "count(*) as target_count,"
            "(select count(distinct b.id)"
            " from santa_bundle as b"
            " join santa_rule as r on (b.target_id = r.target_id)) as rule_count "
            "from santa_bundle"
        )
        cursor = connection.cursor()
        cursor.execute(query)
        summary = {"total": 0}
        for target_type, target_count, rule_count in cursor.fetchall():
            summary[target_type.lower()] = {"count": target_count, "rule_count": rule_count}
            summary["total"] += target_count
        return summary

    def search_query(self, q=None, target_type=None):
        if not target_type:
            target_type = None
        kwargs = {}
        if q:
            kwargs["q"] = "%{}%".format(connection.ops.prep_for_like_query(q))
            bi_where = "where upper(name) like upper(%(q)s) or upper(identifier) like upper(%(q)s)"
            ce_where = ("where upper(c.common_name) like upper(%(q)s) "
                        "or upper(c.organizational_unit) like upper(%(q)s) "
                        "or upper(c.sha_256) like upper(%(q)s)")
            ti_where = ("where c.organizational_unit ~ '[A-Z0-9]{10}' and ("
                        "upper(c.organization) like upper(%(q)s) "
                        "or upper(c.organizational_unit) like upper(%(q)s))")
            ch_where = "where upper(f.cdhash) like upper(%(q)s)"
            si_where = "where upper(f.signing_id) like upper(%(q)s)"
            bu_where = "where upper(name) like upper(%(q)s) or upper(identifier) like upper(%(q)s)"
        else:
            bi_where = ce_where = bu_where = ""
            ti_where = "where c.organizational_unit ~ '[A-Z0-9]{10}'"
            ch_where = "where f.cdhash IS NOT NULL"
            si_where = "where f.signing_id IS NOT NULL"
        targets_subqueries = {
            "BINARY":
                "select 'BINARY' as target_type,  f.identifier, f.name as sort_str,"
                "jsonb_build_object("
                " 'name', f.name,"
                " 'cert_cn', c.common_name,"
                " 'cert_sha256', c.sha_256,"
                " 'cert_ou', c.organizational_unit"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{bi_where} "
                "group by target_type, f.identifier, f.name, c.common_name, c.sha_256, c.organizational_unit",
            "CERTIFICATE":
                "select 'CERTIFICATE' as target_type, c.sha_256 as identifier, c.common_name as sort_str,"
                "jsonb_build_object("
                " 'cn', c.common_name,"
                " 'ou', c.organizational_unit,"
                " 'valid_from', c.valid_from,"
                " 'valid_until', c.valid_until"
                ") as object "
                "from inventory_certificate as c "
                "join collected_files as f on (c.id = f.signed_by_id) "
                f"{ce_where} "
                "group by target_type, c.sha_256, c.common_name, c.organizational_unit, c.valid_from, c.valid_until",
            "TEAMID":
                "select 'TEAMID' as target_type, c.organizational_unit as identifier, c.organization as sort_str,"
                "jsonb_build_object("
                " 'organizational_unit', c.organizational_unit,"
                " 'organization', c.organization"
                ") as object "
                "from inventory_certificate as c "
                "join collected_files as f on (c.id = f.signed_by_id) "
                f"{ti_where} "
                "group by target_type, c.organizational_unit, c.organization",
            "CDHASH":
                "select 'CDHASH' as target_type, f.cdhash as identifier, f.cdhash as sort_str,"
                "jsonb_build_object("
                " 'file_name', f.name,"
                " 'cert_cn', c.common_name"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{ch_where} "
                "group by target_type, f.cdhash, f.name, c.common_name",
            "SIGNINGID":
                "select 'SIGNINGID' as target_type, f.signing_id as identifier, f.signing_id as sort_str,"
                "jsonb_build_object("
                " 'file_name', f.name,"
                " 'cert_cn', c.common_name"
                ") as object "
                "from collected_files as f "
                "left join inventory_certificate as c on (f.signed_by_id = c.id) "
                f"{si_where} "
                "group by target_type, f.signing_id, f.name, c.common_name",
            "BUNDLE":
                "select 'BUNDLE' as target_type, t.identifier, b.name as sort_str,"
                "jsonb_build_object("
                " 'name', b.name,"
                " 'version', b.version,"
                " 'version_str', b.version_str"
                ") as object "
                "from santa_bundle as b "
                "join santa_target as t on (b.target_id = t.id) "
                f"{bu_where} "
        }
        targets_query = " union ".join(v for k, v in targets_subqueries.items()
                                       if target_type is None or k == target_type)
        query = (
            "with collected_files as ("
            "  select f.sha_256 as identifier, f.cdhash, f.signed_by_id, f.signing_id, f.name"
            "  from inventory_file as f"
            "  join inventory_source as s on (f.source_id = s.id)"
            "  where s.module='zentral.contrib.santa' and s.name = 'Santa events'"
            "  group by f.sha_256, f.cdhash, f.signed_by_id, f.signing_id, f.name"
            f"), targets as ({targets_query}) "
            "select target_type, identifier, object, count(*) over() as full_count,"
            "(select count(*) from santa_rule as r"
            " join santa_target as t on (r.target_id = t.id)"
            " where t.type = ts.target_type and t.identifier = ts.identifier) as rule_count "
            "from targets as ts "
            "order by sort_str, identifier "
        )
        return query, kwargs

    def search(self, q=None, target_type=None, offset=0, limit=10):
        query, kwargs = self.search_query(q, target_type)
        kwargs.update({"offset": offset, "limit": limit})
        cursor = connection.cursor()
        cursor.execute(f"{query} offset %(offset)s limit %(limit)s", kwargs)
        columns = [col[0] for col in cursor.description]
        results = []
        type_dict = dict(Target.TYPE_CHOICES)
        for row in cursor.fetchall():
            result = dict(zip(columns, row))
            obj = json.loads(result.pop("object"))
            for attr in ("valid_from", "valid_until"):
                if attr in obj:
                    obj[attr] = parser.parse(obj[attr])
            result["object"] = obj
            url_name = result["target_type"].lower()
            result["target_type_for_display"] = type_dict.get(result["target_type"], result["target_type"])
            result["url"] = reverse(f"santa:{url_name}", args=(result["identifier"],))
            results.append(result)
        return results

    def get_teamid_objects(self, identifier):
        query = (
            "select c.organizational_unit, c.organization "
            "from inventory_certificate as c "
            "join inventory_file as f on (f.signed_by_id = c.id) "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and c.organizational_unit = %s "
            "group by c.organizational_unit, c.organization "
            "order by c.organization, c.organizational_unit"
        )
        cursor = connection.cursor()
        cursor.execute(query, [identifier])
        nt_teamid = namedtuple('TeamID', [col[0] for col in cursor.description])
        return [nt_teamid(*row) for row in cursor.fetchall()]

    def search_teamid_objects(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        q = "%{}%".format(connection.ops.prep_for_like_query(q))
        query = (
            "select c.organizational_unit, c.organization "
            "from inventory_certificate as c "
            "join inventory_file as f on (f.signed_by_id = c.id) "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and ("
            "  upper(c.organizational_unit) like upper(%s)"
            "  or upper(c.organization) like upper(%s)"
            ") "
            "group by c.organizational_unit, c.organization "
            "order by c.organization, c.organizational_unit"
        )
        cursor = connection.cursor()
        cursor.execute(query, [q, q])
        nt_teamid = namedtuple('TeamID', [col[0] for col in cursor.description])
        return [nt_teamid(*row) for row in cursor.fetchall()]

    def get_cdhash_objects(self, identifier):
        query = (
            "select f.cdhash "
            "from inventory_file as f "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and f.cdhash = %s "
            "group by f.cdhash "
            "order by f.cdhash"
        )
        cursor = connection.cursor()
        cursor.execute(query, [identifier])
        nt_cdhash = namedtuple('CDHash', [col[0] for col in cursor.description])
        return [nt_cdhash(*row) for row in cursor.fetchall()]

    def search_cdhash_objects(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        q = "%{}%".format(connection.ops.prep_for_like_query(q))
        query = (
            "select f.cdhash "
            "from inventory_file as f "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and upper(f.cdhash) like upper(%s) "
            "group by f.cdhash "
            "order by f.cdhash"
        )
        cursor = connection.cursor()
        cursor.execute(query, [q])
        nt_cdhash = namedtuple('CDHash', [col[0] for col in cursor.description])
        return [nt_cdhash(*row) for row in cursor.fetchall()]

    def get_signingid_objects(self, identifier):
        query = (
            "select f.signing_id "
            "from inventory_file as f "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and f.signing_id = %s "
            "group by f.signing_id "
            "order by f.signing_id"
        )
        cursor = connection.cursor()
        cursor.execute(query, [identifier])
        nt_signingid = namedtuple('SigningID', [col[0] for col in cursor.description])
        return [nt_signingid(*row) for row in cursor.fetchall()]

    def search_signingid_objects(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        q = "%{}%".format(connection.ops.prep_for_like_query(q))
        query = (
            "select f.signing_id "
            "from inventory_file as f "
            "join inventory_source as s on (s.id = f.source_id) "
            "where s.module = 'zentral.contrib.santa' and s.name = 'Santa events' "
            "and upper(f.signing_id) like upper(%s) "
            "group by f.signing_id "
            "order by f.signing_id"
        )
        cursor = connection.cursor()
        cursor.execute(query, [q])
        nt_signingid = namedtuple('SigningID', [col[0] for col in cursor.description])
        return [nt_signingid(*row) for row in cursor.fetchall()]


class Target(models.Model):
    BINARY = "BINARY"
    BUNDLE = "BUNDLE"
    CDHASH = "CDHASH"
    CERTIFICATE = "CERTIFICATE"
    SIGNING_ID = "SIGNINGID"
    TEAM_ID = "TEAMID"
    TYPE_CHOICES = (
        (BINARY, "Binary"),
        (BUNDLE, "Bundle"),
        (CDHASH, "cdhash"),
        (CERTIFICATE, "Certificate"),
        (SIGNING_ID, "Signing ID"),
        (TEAM_ID, "Team ID"),
    )
    type = models.CharField(choices=TYPE_CHOICES, max_length=16)
    identifier = models.CharField(max_length=256)
    blocked_count = models.IntegerField(default=0)
    collected_count = models.IntegerField(default=0)
    executed_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = TargetManager()

    class Meta:
        unique_together = (("type", "identifier"),)

    def get_absolute_url(self):
        return reverse(f"santa:{self.type.lower()}", args=(self.identifier,))

    @cached_property
    def team_id(self):
        if self.type == self.SIGNING_ID:
            return self.identifier.split(":")[0]
        elif self.type == self.TEAM_ID:
            return self.identifier

    @cached_property
    def files(self):
        if self.type == self.BINARY:
            return list(File.objects.select_related("bundle").filter(sha_256=self.identifier))
        elif self.type == self.CDHASH:
            return list(File.objects.select_related("bundle").filter(cdhash=self.identifier))
        elif self.type == self.SIGNING_ID:
            return list(File.objects.select_related("bundle").filter(signing_id=self.identifier))
        else:
            return []

    @cached_property
    def certificates(self):
        if self.type == self.CERTIFICATE:
            return list(Certificate.objects.filter(sha_256=self.identifier))
        else:
            return []

    @cached_property
    def team_ids(self):
        if self.team_id:
            return Target.objects.get_teamid_objects(self.team_id)
        else:
            return []

    def serialize_for_event(self):
        d = {"type": self.type}
        if self.type == self.CDHASH:
            d["cdhash"] = self.identifier
        elif self.type == self.SIGNING_ID:
            d["signing_id"] = self.identifier
        elif self.type == self.TEAM_ID:
            d["team_id"] = self.identifier
        else:
            d["sha256"] = self.identifier
        return d


class BundleManager(models.Manager):
    def search(self, **kwargs):
        name = kwargs.get("name")
        if name:
            qs = self.filter(Q(name__icontains=name) | Q(bundle_id__icontains=name))
            return (
                qs.select_related("target")
                  .annotate(binary_target_count=Count("binary_targets"))
                  .order_by("name")
            )
        else:
            return []


class Bundle(models.Model):
    target = models.OneToOneField(Target, on_delete=models.PROTECT)

    path = models.TextField()
    executable_rel_path = models.TextField()
    bundle_id = models.TextField()
    name = models.TextField()
    version = models.TextField()
    version_str = models.TextField()

    binary_count = models.PositiveIntegerField()
    binary_targets = models.ManyToManyField(Target, related_name="parent_bundle")
    uploaded_at = models.DateTimeField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = BundleManager()

    def __str__(self):
        return f"{self.bundle_id} {self.version_str}"

    def get_absolute_url(self):
        return reverse("santa:bundle", args=(self.target.identifier,))


class RuleSet(models.Model):
    name = models.CharField(max_length=256, unique=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        return {"pk": self.pk, "name": self.name}


def translate_rule_policy(policy):
    if not isinstance(policy, int):
        policy = int(policy)
    if policy == Rule.ALLOWLIST:
        return "ALLOWLIST"
    elif policy == Rule.ALLOWLIST_COMPILER:
        return "ALLOWLIST_COMPILER"
    elif policy == Rule.BLOCKLIST:
        return "BLOCKLIST"
    elif policy == Rule.SILENT_BLOCKLIST:
        return "SILENT_BLOCKLIST"
    elif policy == MachineRule.REMOVE:
        return "REMOVE"
    else:
        raise ValueError(f"Unknown santa policy: {policy}")


class Rule(models.Model):
    ALLOWLIST = 1
    BLOCKLIST = 2
    SILENT_BLOCKLIST = 3
    ALLOWLIST_COMPILER = 5
    POLICY_CHOICES = (
        (ALLOWLIST, "Allowlist"),
        (BLOCKLIST, "Blocklist"),
        (SILENT_BLOCKLIST, "Silent blocklist"),
        (ALLOWLIST_COMPILER, "Allowlist compiler"),
    )
    BUNDLE_POLICIES = (ALLOWLIST, ALLOWLIST_COMPILER)
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    ruleset = models.ForeignKey(RuleSet, on_delete=models.CASCADE, null=True)

    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    policy = models.PositiveSmallIntegerField(choices=POLICY_CHOICES)
    custom_msg = models.TextField(blank=True)
    description = models.TextField(blank=True)
    version = models.PositiveIntegerField(default=1)

    # scope
    serial_numbers = ArrayField(models.TextField(), blank=True, default=list)
    excluded_serial_numbers = ArrayField(models.TextField(), blank=True, default=list)
    primary_users = ArrayField(models.TextField(), blank=True, default=list)
    excluded_primary_users = ArrayField(models.TextField(), blank=True, default=list)
    tags = models.ManyToManyField(Tag, blank=True, related_name="+")
    excluded_tags = models.ManyToManyField(Tag, blank=True, related_name="+")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("configuration", "target"),)

    def is_blocking_rule(self):
        return self.policy in (self.BLOCKLIST, self.SILENT_BLOCKLIST)

    def get_absolute_url(self):
        return reverse("santa:configuration_rules", args=(self.configuration_id,)) + f"#rule-{self.pk}"

    def get_translated_policy(self):
        return translate_rule_policy(self.policy)

    def serialize_for_event(self):
        d = {
            "configuration": self.configuration.serialize_for_event(keys_only=True),
            "target": self.target.serialize_for_event(),
            "policy": self.get_translated_policy(),
        }
        if self.ruleset:
            d["ruleset"] = self.ruleset.serialize_for_event()
        if self.custom_msg:
            d["custom_msg"] = self.custom_msg
        if self.serial_numbers:
            d["serial_numbers"] = sorted(self.serial_numbers)
        if self.excluded_serial_numbers:
            d["excluded_serial_numbers"] = sorted(self.excluded_serial_numbers)
        if self.primary_users:
            d["primary_users"] = sorted(self.primary_users)
        if self.excluded_primary_users:
            d["excluded_primary_users"] = sorted(self.excluded_primary_users)
        tags = list(self.tags.all().order_by("pk"))
        if tags:
            d["tags"] = [t.serialize_for_event(keys_only=True) for t in tags]
        excluded_tags = list(self.excluded_tags.all().order_by("pk"))
        if excluded_tags:
            d["excluded_tags"] = [t.serialize_for_event(keys_only=True) for t in excluded_tags]
        return d


class MachineRuleManager(models.Manager):
    def _iter_new_rules(self, enrolled_machine, tags):
        query = (
            "WITH prepared_rules as ("  # aggregate the tag ids
            "  select r.target_id, r.policy, r.custom_msg, r.version,"
            "  r.serial_numbers, r.primary_users,"
            "  array_remove(array_agg(srt.tag_id), null) as tag_ids,"
            "  r.excluded_serial_numbers, r.excluded_primary_users,"
            "  array_remove(array_agg(sret.tag_id), null) as excluded_tag_ids"
            "  from santa_rule as r"
            "  left join santa_rule_tags as srt on (srt.rule_id = r.id)"
            "  left join santa_rule_excluded_tags as sret on (sret.rule_id = r.id)"
            "  where r.configuration_id = %(configuration_pk)s"
            "  group by r.target_id, r.policy, r.custom_msg, r.version,"
            "  r.serial_numbers, r.excluded_serial_numbers,"
            "  r.primary_users, r.excluded_primary_users"
            "), filtered_rules as ("  # filter the configured rules for the enrolled machine
            "  select pr.target_id, pr.policy, pr.custom_msg, pr.version"
            "  from prepared_rules as pr"
            "  where ("
            "    {wheres}"
            "  )"
            "), expanded_rules as ("  # expand the bundle rules
            "   select case when bt.target_id is not null then bt.target_id else fr.target_id end as target_id,"
            "   fr.policy, fr.custom_msg, fr.version,"
            "   b.binary_count as file_bundle_binary_count, b.target_id as file_bundle_target_id"
            "   from filtered_rules as fr"
            "   left join santa_bundle as b on (b.target_id = fr.target_id)"
            "   left join santa_bundle_binary_targets as bt on (bt.bundle_id = b.id)"
            "), machine_rules as ("  # current enrolled machine machine rules
            "   select target_id, policy, version"
            "   from santa_machinerule"
            "   where enrolled_machine_id = %(enrolled_machine_pk)s"
            "), rule_product as ("  # full product of the configured rules and the machine rules
            "  select er.target_id as rule_target_id, er.policy as rule_policy,"
            "  er.custom_msg as rule_custom_msg, er.version as rule_version,"
            "  er.file_bundle_binary_count, er.file_bundle_target_id,"
            "  mr.target_id as machine_rule_target_id, mr.policy as machine_rule_policy,"
            "  mr.version as machine_rule_version"
            "  from expanded_rules as er"
            "  full outer join machine_rules as mr on (mr.target_id = er.target_id)"
            "), changed_rules as ("  # filter the product to get the changes
            "  select rule_target_id as target_id, rule_policy as policy,"
            "  rule_custom_msg as custom_msg, rule_version as version,"
            "  file_bundle_binary_count, file_bundle_target_id"
            "  from rule_product where ("
            "    (machine_rule_target_id is null)"
            "    or (rule_target_id is not null"
            "        and (rule_policy <> machine_rule_policy or rule_version <> machine_rule_version)))"
            "  union"
            "  select machine_rule_target_id as target_id, 4 as policy, null as custom_msg, 1 as version,"
            "  null as file_bundle_binary_count, null as file_bundle_target_id"
            "  from rule_product where rule_target_id is null"
            ") "  # limit, order and join with target to get all the necessary info
            "select t.id as target_id, t.type as rule_type, t.identifier, cr.policy, cr.custom_msg, cr.version,"
            "cr.file_bundle_binary_count, t2.identifier as file_bundle_hash "
            "from changed_rules as cr "
            "join santa_target as t on (t.id = cr.target_id) "
            "left join santa_target as t2 on (t2.id = cr.file_bundle_target_id) "
            "order by t.identifier limit %(batch_size)s"
        )
        configuration = enrolled_machine.enrollment.configuration
        # machine specific rules
        wheres = ["(cardinality(pr.serial_numbers) = 0 or %(serial_number)s = ANY(pr.serial_numbers))",
                  "%(serial_number)s <> ALL(pr.excluded_serial_numbers)"]
        kwargs = {"configuration_pk": configuration.pk,
                  "serial_number": enrolled_machine.serial_number,
                  "enrolled_machine_pk": enrolled_machine.pk,
                  "batch_size": configuration.batch_size}
        if enrolled_machine.primary_user:
            # user specific rules
            wheres.extend(["(cardinality(pr.primary_users) = 0 or %(primary_user)s = ANY(pr.primary_users))",
                           "%(primary_user)s <> ALL(pr.excluded_primary_users)"])
            kwargs["primary_user"] = enrolled_machine.primary_user
        else:
            wheres.extend(["cardinality(pr.primary_users) = 0",
                           "cardinality(pr.excluded_primary_users) = 0"])
        if tags:
            # tag specific rules
            wheres.extend(["(cardinality(pr.tag_ids) = 0 or %(tags)s && pr.tag_ids)",
                           "not (%(tags)s && pr.excluded_tag_ids)"])
            kwargs["tags"] = tags
        else:
            wheres.append("cardinality(pr.tag_ids) = 0")
        query = query.format(wheres=" and ".join(wheres))
        cursor = connection.cursor()
        cursor.execute(query, kwargs)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            rule_info_d = {}
            for key, val in zip(columns, row):
                if val is not None:
                    rule_info_d[key] = val
            yield rule_info_d

    def get_next_rule_batch(self, enrolled_machine, tags, cursor=None):
        qs = self.filter(enrolled_machine=enrolled_machine).select_for_update()

        # fresh start from last known OK state
        # remove all unacknowlegded machine rules, except the REMOVE ones
        # this will ultimately refresh all the rules that haven't been acknowleged
        qs_cleanup = qs.exclude(policy=MachineRule.REMOVE).filter(cursor__isnull=False)
        if cursor:
            # do not delete request cursor rules. We will acknowlege them
            qs_cleanup = qs_cleanup.exclude(cursor=cursor)
        qs_cleanup.delete()

        # acknowlege the cursor rules
        if cursor:
            qs = qs.filter(cursor=cursor)
            # remove the REMOVE machine rules from the last batch
            qs.filter(policy=MachineRule.REMOVE).delete()
            # acknowlege the other machine rules from the last batch
            qs.update(cursor=None)

        # translate attributes for older santa agents
        # TODO remove eventually

        # return next batch
        rules = []
        new_cursor = None
        use_sha256_attr = enrolled_machine.get_comparable_santa_version() < (2022, 1)
        for rule in self._iter_new_rules(enrolled_machine, tags):
            if new_cursor is None:
                new_cursor = get_random_string(8)
            target_id = rule.pop("target_id")
            policy = rule.pop("policy")  # need a translation
            rule["policy"] = translate_rule_policy(policy)
            version = rule.pop("version")
            if policy == MachineRule.REMOVE or not rule["custom_msg"]:
                rule.pop("custom_msg", None)
            if use_sha256_attr and rule["rule_type"] not in (Target.CDHASH, Target.SIGNING_ID, Target.TEAM_ID):
                rule["sha256"] = rule.pop("identifier")
            self.update_or_create(enrolled_machine=enrolled_machine,
                                  target=Target(pk=target_id),
                                  defaults={
                                      "policy": policy,
                                      "version": version,
                                      "cursor": new_cursor,
                                  })
            rules.append(rule)
        response_cursor = None
        if len(rules):
            response_cursor = new_cursor
        return rules, response_cursor


class MachineRule(models.Model):
    REMOVE = 4
    POLICY_CHOICES = Rule.POLICY_CHOICES + (
        (REMOVE, "Remove"),
    )
    enrolled_machine = models.ForeignKey(EnrolledMachine, on_delete=models.CASCADE)
    target = models.ForeignKey(Target, on_delete=models.PROTECT)
    policy = models.PositiveSmallIntegerField(choices=POLICY_CHOICES)
    version = models.PositiveIntegerField()
    cursor = models.CharField(max_length=8, null=True)

    objects = MachineRuleManager()

    class Meta:
        unique_together = (("enrolled_machine", "target"),)
