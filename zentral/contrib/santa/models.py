import logging
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import connection, models
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import BaseEnrollment, Certificate, OSXApp
from zentral.utils.mt_models import AbstractMTObject, MTObjectManager

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
    LOCAL_CONFIGURATION_ATTRIBUTES = {
        'client_mode',
        'file_changes_regex',
        'file_changes_prefix_filters',
        'allowed_path_regex',
        'blocked_path_regex',
        'enable_page_zero_protection',
        'enable_bad_signature_protection',
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
    # https://github.com/google/santa/blob/master/Docs/deployment/configuration.md#sync-server-provided-configuration

    batch_size = models.IntegerField(
        default=DEFAULT_BATCH_SIZE,
        validators=[MinValueValidator(5), MaxValueValidator(100)],
        help_text="The number of rules to download or events to upload per request. "
                  "Multiple requests will be made if there is more work than can fit in single request."
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
    hardware_uuid = models.UUIDField()
    serial_number = models.TextField()

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("enrollment", "hardware_uuid")


# Collected applications


class CollectedApplicationManager(MTObjectManager):
    def search(self, **kwargs):
        qs = self.all()
        name = kwargs.get("name")
        if name:
            qs = qs.filter(name__icontains=name)
            return qs.select_related("bundle").order_by("bundle__bundle_name", "name")
        else:
            return []

    def search_certificates(self, **kwargs):
        q = kwargs.get("query")
        if not q:
            return []
        else:
            query = (
                "WITH RECURSIVE certificates AS ("
                "SELECT c1.id, c1.signed_by_id "
                "FROM inventory_certificate AS c1 "
                "JOIN santa_collectedapplication ca ON (ca.signed_by_id = c1.id) "

                "UNION "

                "SELECT c2.id, c2.signed_by_id "
                "FROM inventory_certificate AS c2 "
                "JOIN certificates c ON (c.signed_by_id = c2.id)"
                ") SELECT * FROM inventory_certificate c3 "
                "JOIN certificates AS c ON (c.id = c3.id) "
                "WHERE UPPER(c3.common_name) LIKE UPPER(%s) "
                "OR UPPER(c3.organization) LIKE UPPER(%s) "
                "OR UPPER(c3.organizational_unit) LIKE UPPER(%s) "
                "ORDER BY c3.common_name, c3.organization, c3.organizational_unit;"
            )
            print(query)
            q = "%{}%".format(connection.ops.prep_for_like_query(q))
            return Certificate.objects.raw(query, [q, q, q])


class CollectedApplication(AbstractMTObject):
    name = models.TextField()
    path = models.TextField()
    sha_256 = models.CharField(max_length=64, db_index=True)
    bundle = models.ForeignKey(OSXApp, on_delete=models.PROTECT, blank=True, null=True)
    bundle_path = models.TextField(blank=True, null=True)
    signed_by = models.ForeignKey(Certificate, on_delete=models.PROTECT, blank=True, null=True)

    objects = CollectedApplicationManager()
