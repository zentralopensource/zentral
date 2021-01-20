import logging
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.postgres.fields import ArrayField
from django.db import connection, models
from django.db.models import Count, Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from zentral.contrib.inventory.models import BaseEnrollment, Certificate, File, Tag


logger = logging.getLogger("zentral.contrib.santa.models")


# Configuration / Enrollment


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
    LOCAL_CONFIGURATION_ATTRIBUTES = {
        'client_mode',
        'file_changes_regex',
        'file_changes_prefix_filters',
        'allowed_path_regex',
        'blocked_path_regex',
        'enable_page_zero_protection',
        'enable_bad_signature_protection',
        'enable_sysx_cache',
        'more_info_url',
        'event_detail_url',
        'event_detail_text',
        'unknown_block_message',
        'banned_block_message',
        'mode_notification_monitor',
        'mode_notification_lockdown',
        'machine_owner_plist',
        'machine_owner_key',
        'client_auth_certificate_issuer_cn',
    }
    SYNC_SERVER_CONFIGURATION_ATTRIBUTES = {
        # 'client_mode', has to be translated to a string value
        'batch_size',
        'full_sync_interval',
        'allowed_path_regex',
        'blocked_path_regex',
        'enable_bundles',
        'enable_transitive_rules'
    }
    DEPRECATED_ATTRIBUTES_MAPPING_1_14 = {
        'allowed_path_regex': 'whitelist_regex',
        'blocked_path_regex': 'blacklist_regex',
        'enable_transitive_rules': 'enabled_transitive_whitelisting',
    }

    name = models.CharField(max_length=256, unique=True)

    client_mode = models.IntegerField(choices=CLIENT_MODE_CHOICES, default=MONITOR_MODE)
    file_changes_regex = models.TextField(
        blank=True,
        help_text="The regex of paths to log file changes. Regexes are specified in ICU format."
    )
    file_changes_prefix_filters = models.TextField(
        blank=True,
        help_text=("A list of ignore prefixes which are checked in-kernel. "
                   "This is more performant than FileChangesRegex when ignoring whole directory trees.")
    )
    allowed_path_regex = models.TextField(
        blank=True,
        help_text="Matching binaries will be allowed to run, in both modes."
                  "Events will be logged with the 'ALLOW_SCOPE' decision."
    )
    blocked_path_regex = models.TextField(
        blank=True,
        help_text="In Monitor mode, executables whose paths are matched by this regex will be blocked."
    )
    enable_page_zero_protection = models.BooleanField(
        default=True,
        help_text="If this flag is set to YES, 32-bit binaries that are missing the __PAGEZERO segment will be blocked"
                  " even in MONITOR mode, unless the binary is whitelisted by an explicit rule."
    )
    enable_bad_signature_protection = models.BooleanField(
        default=False,
        help_text="When enabled, a binary that is signed but has a bad signature (cert revoked, binary tampered with, "
                  "etc.) will be blocked regardless of client-mode unless a binary whitelist."
    )
    enable_sysx_cache = models.BooleanField(
        "Enable system extension cache",
        default=False,
        help_text="When enabled, a self-managed cache for decision responses will be used to help improve performance "
                  "when running Santa as a system extension alongside another system extension."
    )
    more_info_url = models.URLField(
        blank=True,
        help_text='The URL to open when the user clicks "More Info..." when opening Santa.app. '
                  'If unset, the button will not be displayed.'
    )
    event_detail_url = models.URLField(
        blank=True,
        help_text="When the user gets a block notification, a button can be displayed which will take them "
                  "to a web page with more information about that event."
                  "This property contains a kind of format string to be turned into the URL to send them to. "
                  "The following sequences will be replaced in the final URL: "
                  "%file_sha%, "
                  "%machine_id%, "
                  "%username%, "
                  "%bundle_id%, "
                  "%bundle_ver%."
    )
    event_detail_text = models.TextField(
        blank=True,
        help_text="Related to the above property, this string represents the text to show on the button."
    )
    unknown_block_message = models.TextField(
        default="The following application has been blocked from executing<br/>\n"
                "because its trustworthiness cannot be determined.",
        help_text="In Lockdown mode this is the message shown to the user when an unknown binary is blocked."
    )
    banned_block_message = models.TextField(
        default="The following application has been blocked from executing<br/>\n"
                "because it has been deemed malicious.",
        help_text="This is the message shown to the user when a binary is blocked because of a rule "
                  "if that rule doesn't provide a custom message."
    )
    mode_notification_monitor = models.TextField(
        default="Switching into Monitor mode",
        help_text="The notification text to display when the client goes into Monitor mode."
    )
    mode_notification_lockdown = models.TextField(
        default="Switching into Lockdown mode",
        help_text="The notification text to display when the client goes into Lockdown mode."
    )
    machine_owner_plist = models.CharField(
        blank=True,
        max_length=512,
        help_text="The path to a plist that contains the machine owner key / value pair."
    )
    machine_owner_key = models.CharField(
        blank=True,
        max_length=128,
        help_text="The key to use on the machine owner plist."
    )

    # TLS

    # for the client cert authentication
    client_certificate_auth = models.BooleanField(
        "Client certificate authentication",
        default=False,
        help_text="If set, a client certificate will be required for sync authentication. "
                  "Santa will automatically look for a matching certificate "
                  "and its private key in the System keychain, "
                  "if the TLS server advertises the accepted CA certificates. "
                  "If the CA certificates are not sent to the client, "
                  "use the Client Auth Certificate Issuer CN setting."
    )
    client_auth_certificate_issuer_cn = models.CharField(
        "Client auth certificate issuer CN",
        blank=True,
        max_length=255,
        help_text="If set, this is the Issuer Name of a certificate in the System keychain "
                  "to be used for sync authentication. "
                  "The corresponding private key must also be in the keychain."
    )

    # the extra ones only provided via server sync
    # https://santa.readthedocs.io/en/latest/deployment/configuration/#sync-server-provided-configuration

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

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("santa:configuration", args=(self.pk,))

    def is_monitor_mode(self):
        return self.client_mode == self.MONITOR_MODE

    def get_sync_server_config(self, santa_version):
        config = {k: getattr(self, k)
                  for k in self.SYNC_SERVER_CONFIGURATION_ATTRIBUTES}

        # translate client mode
        if self.client_mode == self.MONITOR_MODE:
            config["client_mode"] = self.PREFLIGHT_MONITOR_MODE
        elif self.client_mode == self.LOCKDOWN_MODE:
            config["client_mode"] = self.PREFLIGHT_LOCKDOWN_MODE
        else:
            raise NotImplementedError("Unknown santa client mode: {}".format(self.client_mode))

        # provide non matching regexp if the regexp are empty
        for attr in ("allowed_path_regex",
                     "blocked_path_regex"):
            if not config.get(attr):
                config[attr] = "NON_MATCHING_PLACEHOLDER_{}".format(get_random_string(8))

        # translate attributes for older santa agents
        santa_version = tuple(int(i) for i in santa_version.split("."))
        if santa_version < (1, 14):
            for attr, deprecated_attr in self.DEPRECATED_ATTRIBUTES_MAPPING_1_14.items():
                config[deprecated_attr] = config.pop(attr)

        return config

    def get_local_config(self, min_supported_santa_version=(1, 13)):
        config = {}
        for k in self.LOCAL_CONFIGURATION_ATTRIBUTES:
            v = getattr(self, k)
            if not v:
                continue
            if min_supported_santa_version < (1, 14) and k in self.DEPRECATED_ATTRIBUTES_MAPPING_1_14:
                k = self.DEPRECATED_ATTRIBUTES_MAPPING_1_14[k]
            config_attr_items = []
            for i in k.split("_"):
                if i == "url":
                    i = "URL"
                elif i == "cn":
                    i = "CN"
                else:
                    i = i.capitalize()
                config_attr_items.append(i)
            config_attr = "".join(config_attr_items)
            config[config_attr] = v
        return config

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)

    def get_description_for_distributor(self):
        return "Santa configuration: {}".format(self.configuration)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = {"pk": self.configuration.pk,
                                            "name": self.configuration.name}
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("santa:configuration", args=(self.configuration.pk,)), self.pk)


class EnrolledMachine(models.Model):
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)

    hardware_uuid = models.UUIDField()  # DB index?
    serial_number = models.TextField()

    primary_user = models.TextField(null=True)
    client_mode = models.IntegerField(choices=Configuration.CLIENT_MODE_CHOICES)
    santa_version = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("enrollment", "hardware_uuid")


# Rules


class Target(models.Model):
    BINARY = "BINARY"
    BUNDLE = "BUNDLE"
    CERTIFICATE = "CERTIFICATE"
    TYPE_CHOICES = (
        (BINARY, "Binary"),
        (BUNDLE, "Bundle"),
        (CERTIFICATE, "Certificate"),
    )
    type = models.CharField(choices=TYPE_CHOICES, max_length=16)
    sha256 = models.CharField(max_length=64)

    class Meta:
        unique_together = (("type", "sha256"),)

    @cached_property
    def files(self):
        if self.type == self.BINARY:
            return list(File.objects.select_related("bundle").filter(sha_256=self.sha256))
        else:
            return []

    @cached_property
    def certificates(self):
        if self.type == self.CERTIFICATE:
            return list(Certificate.objects.filter(sha_256=self.sha256))
        else:
            return []


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


class RuleSet(models.Model):
    name = models.CharField(max_length=256, unique=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name


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
    version = models.PositiveIntegerField(default=1)

    # scope
    serial_numbers = ArrayField(models.TextField(), blank=True, default=list)
    primary_users = ArrayField(models.TextField(), blank=True, default=list)
    tags = models.ManyToManyField(Tag, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = (("configuration", "target"),)

    def is_blocking_rule(self):
        return self.policy in (self.BLOCKLIST, self.SILENT_BLOCKLIST)

    def get_absolute_url(self):
        return reverse("santa:configuration_rules", args=(self.configuration_id,))


def translate_rule_policy(policy):
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


class MachineRuleManager(models.Manager):
    def _iter_new_rules(self, enrolled_machine, tags):
        query = (
            "WITH prepared_rules as ("  # aggregate the tag ids
            "  select r.target_id, r.policy, r.custom_msg, r.version,"
            "  r.serial_numbers, r.primary_users, array_remove(array_agg(srt.tag_id), null) as tag_ids"
            "  from santa_rule as r"
            "  left join santa_rule_tags as srt on (srt.rule_id = r.id)"
            "  where r.configuration_id = %s"
            "  group by r.target_id, r.policy, r.custom_msg, r.version, r.serial_numbers, r.primary_users"
            "), filtered_rules as ("  # filter the configured rules for the enrolled machine
            "  select pr.target_id, pr.policy, pr.custom_msg, pr.version"
            "  from prepared_rules as pr"
            "  where ("
            "    (cardinality(pr.serial_numbers) = 0"
            "     and cardinality(pr.primary_users) = 0"
            "     and cardinality(pr.tag_ids) = 0) or ("
            "    {wheres}"
            "  ))"
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
            "   where enrolled_machine_id = %s"
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
            "select t.id as target_id, t.type as rule_type, t.sha256, cr.policy, cr.custom_msg, cr.version,"
            "cr.file_bundle_binary_count, t2.sha256 as file_bundle_hash "
            "from changed_rules as cr "
            "join santa_target as t on (t.id = cr.target_id) "
            "left join santa_target as t2 on (t2.id = cr.file_bundle_target_id) "
            "order by t.sha256 limit %s"
        )
        configuration = enrolled_machine.enrollment.configuration
        args = [configuration.pk, enrolled_machine.serial_number]
        wheres = ["%s = ANY(pr.serial_numbers)"]  # machine specific rules
        if enrolled_machine.primary_user:
            wheres.append("%s = ANY(pr.primary_users)")  # user specific rules
            args.append(enrolled_machine.primary_user)
        if tags:
            wheres.append("%s && pr.tag_ids")  # tag specific rules
            args.append(tags)
        args.extend([enrolled_machine.pk, configuration.batch_size])
        query = query.format(wheres=" or ".join(wheres))
        cursor = connection.cursor()
        cursor.execute(query, args)
        columns = [col[0] for col in cursor.description]
        for row in cursor.fetchall():
            rule_info_d = {}
            for key, val in zip(columns, row):
                if val is not None:
                    rule_info_d[key] = val
            yield rule_info_d

    def get_next_rule_batch(self, enrolled_machine, tags, cursor=None):
        qs = self.filter(enrolled_machine=enrolled_machine).select_for_update()
        if cursor is None:
            # fresh start, from last known OK state
            # remove all unacknowlegded machine rules, except the REMOVE ones
            # this will ultimately refresh all the rules that haven't been acknowleged
            qs.exclude(policy=MachineRule.REMOVE).filter(cursor__isnull=False).delete()
        else:
            qs = qs.filter(cursor=cursor)
            # remove the REMOVE machine rules from the last batch
            qs.filter(policy=MachineRule.REMOVE).delete()
            # acknowlege the other machine rules from the last batch
            qs.update(cursor=None)
        rules = []
        new_cursor = None
        for rule in self._iter_new_rules(enrolled_machine, tags):
            if new_cursor is None:
                new_cursor = get_random_string(8)
            target_id = rule.pop("target_id")
            policy = rule.pop("policy")  # need a translation
            rule["policy"] = translate_rule_policy(policy)
            version = rule.pop("version")
            if policy == MachineRule.REMOVE or not rule["custom_msg"]:
                rule.pop("custom_msg", None)
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
