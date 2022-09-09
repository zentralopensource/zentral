from datetime import timedelta
import enum
import logging
import plistlib
import uuid
from django.contrib.postgres.fields import ArrayField
from django.db import connection, models
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string
from django.utils.functional import cached_property
from django.utils.translation import gettext_lazy as _
from realms.models import Realm, RealmUser
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, EnrollmentSecretRequest, MetaMachine
from zentral.core.secret_engines import decrypt, decrypt_str, encrypt, encrypt_str, rewrap
from zentral.utils.iso_3166_1 import ISO_3166_1_ALPHA_2_CHOICES
from zentral.utils.iso_639_1 import ISO_639_1_CHOICES
from zentral.utils.payloads import get_payload_identifier
from .exceptions import EnrollmentSessionStatusError
from .scep import SCEPChallengeType, get_scep_challenge, load_scep_challenge


logger = logging.getLogger("zentral.contrib.mdm.models")


class Channel(enum.Enum):
    Device = "Device"
    User = "User"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)


class Platform(enum.Enum):
    iOS = "iOS"
    iPadOS = "iPadOS"
    macOS = "macOS"
    tvOS = "tvOS"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)

    @classmethod
    def all_values(cls):
        return [i.value for i in cls]


# Push certificates


class PushCertificate(models.Model):
    name = models.CharField(max_length=256, unique=True)
    topic = models.CharField(max_length=256, unique=True)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    certificate = models.BinaryField()
    private_key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'topic')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:push_certificate", args=(self.pk,))

    def can_be_deleted(self):
        return (
            self.enrolleddevice_set.count() == 0
            and self.depenrollment_set.count() == 0
            and self.otaenrollment_set.count() == 0
            and self.userenrollment_set.count() == 0
        )

    # secret

    def _get_secret_engine_kwargs(self, field):
        return {"name": self.name, "model": "mdm.pushcertificate", "field": field}

    def get_private_key(self):
        return decrypt(self.private_key, **self._get_secret_engine_kwargs("private_key"))

    def set_private_key(self, private_key):
        self.private_key = encrypt(private_key, **self._get_secret_engine_kwargs("private_key"))

    def rewrap_secrets(self):
        self.private_key = rewrap(self.private_key, **self._get_secret_engine_kwargs("private_key"))


# Blueprint


class Blueprint(models.Model):
    name = models.CharField(max_length=256, unique=True)

    activation = models.JSONField(default=dict, editable=False)
    declaration_items = models.JSONField(default=dict, editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name", "created_at")

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:blueprint", args=(self.pk,))

    @property
    def declarations_token(self):
        return uuid.UUID(self.declaration_items["DeclarationsToken"])


# SCEP


class SCEPConfig(models.Model):
    name = models.CharField(max_length=256, unique=True)
    url = models.URLField()
    key_usage = models.IntegerField(choices=((0, 'None (0)'),
                                             (1, 'Signing (1)'),
                                             (4, 'Encryption (4)'),
                                             (5, 'Signing & Encryption (1 | 4 = 5)')),
                                    default=0,
                                    help_text="A bitmask indicating the use of the key.")
    key_is_extractable = models.BooleanField(default=False,
                                             help_text="If true, the private key can be exported from the keychain.")
    keysize = models.IntegerField(choices=((1024, '1024-bit'),
                                           (2048, '2048-bit'),
                                           (4096, '4096-bit')),
                                  default=2048)
    allow_all_apps_access = models.BooleanField(default=False,
                                                help_text="If true, all apps have access to the private key.")
    challenge_type = models.CharField(max_length=64, choices=SCEPChallengeType.choices())
    challenge_kwargs = models.JSONField(editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:scep_config", args=(self.pk,))

    def get_challenge_kwargs(self):
        challenge = load_scep_challenge(self)
        return challenge.get_kwargs()

    def set_challenge_kwargs(self, kwargs):
        challenge = get_scep_challenge(self)
        challenge.set_kwargs(kwargs)

    def rewrap_secrets(self):
        challenge = load_scep_challenge(self)
        challenge.rewrap_kwargs()

    def can_be_deleted(self):
        return (
            self.depenrollment_set.count() == 0
            and self.otaenrollment_set.count() == 0
            and self.userenrollment_set.count() == 0
        )

# Enrollment


class EnrolledDevice(models.Model):
    # device info
    udid = models.CharField(max_length=36, unique=True)
    enrollment_id = models.TextField(null=True)
    serial_number = models.TextField(db_index=True)
    platform = models.CharField(max_length=64, choices=Platform.choices())

    # push
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.PROTECT)
    token = models.BinaryField(blank=True, null=True)
    push_magic = models.TextField(blank=True, null=True)

    # tokens
    unlock_token = models.TextField(null=True)
    bootstrap_token = models.TextField(null=True)

    # cert
    cert_fingerprint = models.BinaryField(blank=True, null=True)
    cert_not_valid_after = models.DateTimeField(blank=True, null=True)

    blueprint = models.ForeignKey(Blueprint, on_delete=models.SET_NULL, blank=True, null=True)
    awaiting_configuration = models.BooleanField(null=True)
    declarative_management = models.BooleanField(default=False)
    declarations_token = models.UUIDField(null=True)

    # timestamps
    checkout_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.udid

    def get_absolute_url(self):
        return reverse("mdm:enrolled_device", args=(self.pk,))

    # secrets

    def _get_secret_engine_kwargs(self, field):
        if not self.udid:
            raise ValueError("EnrolledDevice must have a UDID")
        return {"field": field, "model": "mdm.enrolleddevice", "udid": self.udid}

    def get_bootstrap_token(self):
        if not self.bootstrap_token:
            return None
        return decrypt(self.bootstrap_token, **self._get_secret_engine_kwargs("bootstrap_token"))

    def set_bootstrap_token(self, token):
        if token is None:
            self.bootstrap_token = None
            return
        self.bootstrap_token = encrypt(token, **self._get_secret_engine_kwargs("bootstrap_token"))

    def get_unlock_token(self):
        if not self.unlock_token:
            return None
        return decrypt(self.unlock_token, **self._get_secret_engine_kwargs("unlock_token"))

    def set_unlock_token(self, token):
        if token is None:
            self.unlock_token = None
            return
        self.unlock_token = encrypt(token, **self._get_secret_engine_kwargs("unlock_token"))

    def rewrap_secrets(self):
        if not self.bootstrap_token and not self.unlock_token:
            return
        if self.bootstrap_token:
            self.bootstrap_token = rewrap(self.bootstrap_token, **self._get_secret_engine_kwargs("bootstrap_token"))
        if self.unlock_token:
            self.unlock_token = rewrap(self.unlock_token, **self._get_secret_engine_kwargs("unlock_token"))

    def get_urlsafe_serial_number(self):
        if self.serial_number:
            return MetaMachine(self.serial_number).get_urlsafe_serial_number()

    def purge_state(self):
        # TODO purge tokens?
        self.declarative_management = False
        self.save()
        self.commands.all().delete()
        self.installed_artifacts.all().delete()
        self.enrolleduser_set.all().delete()

    def do_checkout(self):
        self.token = self.push_magic = self.bootstrap_token = self.unlock_token = None
        self.checkout_at = timezone.now()
        self.purge_state()
        self.save()

    def can_be_poked(self):
        now = timezone.now()
        return (
            self.checkout_at is None
            and self.push_certificate is not None
            and self.push_certificate.not_before < now
            and now < self.push_certificate.not_after
            and self.token is not None
            and self.push_magic is not None
        )

    def iter_enrollment_session_info(self):
        query = (
            "WITH sessions AS ("
            "  SELECT 'DEP' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'DEP' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_depenrollmentsession s"
            "  JOIN mdm_depenrollment e ON (s.dep_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s"

            "UNION"

            "  SELECT 'OTA' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'OTA' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_otaenrollmentsession s"
            "  JOIN mdm_otaenrollment e ON (s.ota_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s"

            "UNION"

            "  SELECT 'RE' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  CASE"
            "  WHEN d.id IS NOT NULL THEN 'DEP'"
            "  WHEN o.id IS NOT NULL THEN 'OTA'"
            "  WHEN u.id IS NOT NULL THEN 'USER'"
            "  END enrollment_type,"
            "  COALESCE(d.name, o.name, u.name) enrollment_name,"
            "  COALESCE(d.id, o.id, u.id) enrollment_id"
            "  FROM mdm_reenrollmentsession s"
            "  LEFT JOIN mdm_depenrollment d ON (s.dep_enrollment_id = d.id)"
            "  LEFT JOIN mdm_otaenrollment o ON (s.ota_enrollment_id = o.id)"
            "  LEFT JOIN mdm_userenrollment u ON (s.user_enrollment_id = u.id)"
            "  WHERE s.enrolled_device_id = %s"

            "UNION"

            "  SELECT 'USER' session_type, s.id, s.realm_user_id, s.status, s.updated_at, s.created_at,"
            "  'USER' enrollment_type, e.name enrollment_name, e.id enrollment_id"
            "  FROM mdm_userenrollmentsession s"
            "  JOIN mdm_userenrollment e ON (s.user_enrollment_id = e.id)"
            "  WHERE s.enrolled_device_id = %s"
            ") SELECT s.*,  u.username realm_username "
            "FROM sessions s "
            "LEFT JOIN realms_realmuser u ON (s.realm_user_id = u.uuid) "
            "ORDER BY s.created_at DESC;"
        )
        cursor = connection.cursor()
        cursor.execute(query, [self.pk, self.pk, self.pk, self.pk])
        columns = [c.name for c in cursor.description]
        for t in cursor.fetchall():
            yield dict(zip(columns, t))


class EnrolledUser(models.Model):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)

    # user info
    user_id = models.CharField(max_length=36, unique=True)
    enrollment_id = models.TextField(null=True)
    long_name = models.TextField()
    short_name = models.TextField()

    # push
    token = models.BinaryField()

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.long_name or self.short_name

    def get_absolute_url(self):
        return reverse("mdm:enrolled_user", args=(self.enrolled_device.pk, self.pk,))


# Common base model for the DEP, OTA and user enrollment sessions


class EnrollmentSession(models.Model):
    realm_user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, blank=True, null=True)
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def get_common_name(self):
        return "{prefix}${secret}".format(prefix=self.get_prefix(),
                                          secret=self.enrollment_secret.secret)

    def get_organization(self):
        return "MBU${}".format(self.enrollment_secret.meta_business_unit.pk)

    def get_serial_number(self):
        try:
            return self.enrollment_secret.serial_numbers[0]
        except (IndexError, TypeError):
            pass

    def get_urlsafe_serial_number(self):
        serial_number = self.get_serial_number()
        if serial_number:
            return MetaMachine(serial_number).get_urlsafe_serial_number()

    def get_payload_name(self):
        return "Zentral - {prefix} Enrollment SCEP".format(prefix=" - ".join(self.get_prefix().split("$")))

    def is_completed(self):
        return self.status == self.COMPLETED

    def serialize_for_event(self, enrollment_session_type, extra_dict):
        d = {"pk": self.pk,
             "type": enrollment_session_type,
             "status": self.status}
        return {"enrollment_session": d}

    # status update methods

    def _set_next_status(self, next_status, test, **update_dict):
        if test:
            self.status = next_status
            for attr, val in update_dict.items():
                setattr(self, attr, val)
            self.save()
        else:
            raise EnrollmentSessionStatusError(self, next_status)


# Abstract MDM enrollment model


class MDMEnrollment(models.Model):
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.PROTECT)

    scep_config = models.ForeignKey(SCEPConfig, on_delete=models.PROTECT)
    scep_verification = models.BooleanField(
        default=False,
        help_text="Set to true if the SCEP service is configured to post the CSR to Zentral for verification. "
                  "If true, successful verifications will be required during the enrollments."
    )

    blueprint = models.ForeignKey(Blueprint, on_delete=models.SET_NULL, blank=True, null=True)

    # linked to an auth realm
    # if linked, a user has to authenticate to get the mdm payload.
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


# OTA Enrollment


class OTAEnrollment(MDMEnrollment):
    name = models.CharField(max_length=256, unique=True)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="ota_enrollment")
    # if linked to an auth realm, a user has to authenticate to get the mdm payload.

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "name": self.name,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"ota_enrollment": d}

    def get_absolute_url(self):
        return reverse("mdm:ota_enrollment", args=(self.pk,))

    def get_enroll_full_url(self):
        if self.realm:
            return "{}{}".format(settings["api"]["tls_hostname"],
                                 reverse("mdm:ota_enrollment_enroll", args=(self.pk,)))

    def revoke(self):
        if not self.enrollment_secret.revoked_at:
            # TODO events
            self.enrollment_secret.revoked_at = timezone.now()
            self.enrollment_secret.save()
            self.save()


class OTAEnrollmentSessionManager(models.Manager):
    def create_from_realm_user(self, ota_enrollment, realm_user):
        enrollment_secret = ota_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            quota=3,  # Verified three times: config profile download + 2 different SCEP payloads
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix, ota or mdm$ota
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.PHASE_1,
                                        ota_enrollment=ota_enrollment,
                                        realm_user=realm_user,
                                        enrollment_secret=new_es)
        enrollment_session.save()
        return enrollment_session

    def create_from_machine_info(self, ota_enrollment, serial_number, udid):
        # Build a new secret that can be used only by one specific machine
        enrollment_secret = ota_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            serial_numbers=[serial_number],
            udids=[udid],
            quota=2,  # Verified twice with 2 different SCEP payloads
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix, ota or mdm$ota
        new_es.tags.set(tags)
        return self.create(status=self.model.PHASE_2,
                           ota_enrollment=ota_enrollment,
                           enrollment_secret=new_es)


class OTAEnrollmentSession(EnrollmentSession):
    PHASE_1 = "PHASE_1"
    PHASE_2 = "PHASE_2"
    PHASE_2_SCEP_VERIFIED = "PHASE_2_SCEP_VERIFIED"
    PHASE_3 = "PHASE_3"
    PHASE_3_SCEP_VERIFIED = "PHASE_3_SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (PHASE_1, _("Phase 1")),
        (PHASE_2, _("Phase 2")),
        (PHASE_2_SCEP_VERIFIED, _("Phase 2 SCEP verified")),
        (PHASE_3, _("Phase 3")),
        (PHASE_3_SCEP_VERIFIED, _("Phase 3 SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    ota_enrollment = models.ForeignKey(OTAEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="ota_enrollment_session")
    phase2_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                       null=True, related_name="+")
    phase2_scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                            null=True, related_name="+")
    phase3_scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT,
                                            null=True, related_name="+")

    objects = OTAEnrollmentSessionManager()

    def get_enrollment(self):
        return self.ota_enrollment

    def get_prefix(self):
        if self.status == self.PHASE_2:
            return "OTA"
        elif self.status == self.PHASE_3:
            return "MDM$OTA"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("ota", self.ota_enrollment.serialize_for_event())

    def get_blueprint(self):
        return self.ota_enrollment.blueprint

    # status update methods

    def set_phase2_status(self, es_request, serial_number, udid):
        test = (serial_number
                and udid
                and self.realm_user
                and self.status == self.PHASE_1
                and not self.phase2_request
                and not self.phase2_scep_request
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_2, test, phase2_request=es_request)
        # restrict enrollment secret to the current machine
        self.enrollment_secret.serial_numbers = [serial_number]
        self.enrollment_secret.udids = [udid]
        self.enrollment_secret.save()

    def set_phase2_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.PHASE_2
                and not self.phase2_scep_request
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_2_SCEP_VERIFIED, test, phase2_scep_request=es_request)

    def set_phase3_status(self):
        if self.ota_enrollment.scep_verification:
            allowed_statuses = (self.PHASE_2_SCEP_VERIFIED,)
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is None
        else:
            allowed_statuses = (self.PHASE_2, self.PHASE_2_SCEP_VERIFIED)
            scep_ok = self.phase3_scep_request is None
        test = (
            scep_ok
            and self.status in allowed_statuses
            and not self.enrolled_device
        )
        self._set_next_status(self.PHASE_3, test)

    def set_phase3_scep_verified_status(self, es_request):
        if self.ota_enrollment.scep_verification:
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is None
        else:
            scep_ok = self.phase3_scep_request is None
        test = (es_request
                and scep_ok
                and self.status == self.PHASE_3
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_3_SCEP_VERIFIED, test, phase3_scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.ota_enrollment.scep_verification:
            allowed_statuses = (self.PHASE_3_SCEP_VERIFIED,)
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is not None
        else:
            allowed_statuses = (self.PHASE_3, self.PHASE_3_SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.ota_enrollment.scep_verification:
            scep_ok = self.phase2_scep_request is not None and self.phase3_scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# DEP Enrollment


class DEPOrganization(models.Model):
    # org type
    EDU = "edu"
    ORG = "org"
    TYPE_CHOICES = (
        (EDU, EDU),
        (ORG, ORG)
    )
    # org version
    V1 = "v1"
    V2 = "v2"
    VERSION_CHOICES = (
        (V1, "ADP"),
        (V2, "ASM"),
    )
    identifier = models.CharField(max_length=128)
    admin_id = models.EmailField()
    name = models.TextField()
    email = models.EmailField()
    phone = models.TextField()
    address = models.TextField()
    type = models.CharField(max_length=3, choices=TYPE_CHOICES)
    version = models.CharField(max_length=2, choices=VERSION_CHOICES)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def address_lines(self):
        return "\n".join(line for line in (line.strip() for line in self.address.split(",")) if line)


class DEPToken(models.Model):
    certificate = models.BinaryField(editable=False)
    private_key = models.TextField(null=True, editable=False)

    consumer_key = models.CharField(max_length=128, null=True, editable=False)
    consumer_secret = models.TextField(null=True, editable=False)
    access_token = models.CharField(max_length=128, null=True, editable=False)
    access_secret = models.TextField(null=True, editable=False)
    access_token_expiry = models.DateTimeField(null=True, editable=False)

    sync_cursor = models.CharField(max_length=128, null=True, editable=False)
    last_synced_at = models.DateTimeField(null=True, editable=False)

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return "DEP token {}".format(self.pk)

    def get_absolute_url(self):
        return reverse("mdm:dep_token", args=(self.pk,))

    def has_expired(self):
        return self.access_token_expiry and self.access_token_expiry <= timezone.now()

    def expires_soon(self):
        # TODO: hard coded 7 days
        return self.access_token_expiry and self.access_token_expiry <= timezone.now() + timedelta(days=7)

    # secret

    def _get_secret_engine_kwargs(self, field):
        if not self.pk:
            raise ValueError("DEPToken must have a pk")
        return {"pk": self.pk, "model": "mdm.deptoken", "field": field}

    def get_private_key(self):
        if self.private_key:
            return decrypt(self.private_key, **self._get_secret_engine_kwargs("private_key"))

    def set_private_key(self, private_key):
        self.private_key = encrypt(private_key, **self._get_secret_engine_kwargs("private_key"))

    def get_consumer_secret(self):
        if self.consumer_secret:
            return decrypt_str(self.consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))

    def set_consumer_secret(self, consumer_secret):
        self.consumer_secret = encrypt_str(consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))

    def get_access_secret(self):
        if self.access_secret:
            return decrypt_str(self.access_secret, **self._get_secret_engine_kwargs("access_secret"))

    def set_access_secret(self, access_secret):
        self.access_secret = encrypt_str(access_secret, **self._get_secret_engine_kwargs("access_secret"))

    def rewrap_secrets(self):
        if self.private_key:
            self.private_key = rewrap(self.private_key, **self._get_secret_engine_kwargs("private_key"))
        if self.consumer_secret:
            self.consumer_secret = rewrap(self.consumer_secret, **self._get_secret_engine_kwargs("consumer_secret"))
        if self.access_secret:
            self.access_secret = rewrap(self.access_secret, **self._get_secret_engine_kwargs("access_secret"))


class DEPVirtualServer(models.Model):
    name = models.TextField(editable=False)
    uuid = models.UUIDField(unique=True, editable=False)

    organization = models.ForeignKey(DEPOrganization, on_delete=models.PROTECT, editable=False)
    token = models.OneToOneField(DEPToken, on_delete=models.SET_NULL,
                                 editable=False, null=True, related_name="virtual_server")

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_virtual_server", args=(self.pk,))


class DEPEnrollment(MDMEnrollment):
    # https://developer.apple.com/documentation/devicemanagement/skipkeys
    SKIPPABLE_SETUP_PANES = (
        ("Accessibility", True),
        ("Android", True),
        ("Appearance", False),
        ("AppleID", True),
        ("Biometric", False),
        ("DeviceToDeviceMigration", True),
        ("Diagnostics", True),
        ("DisplayTone", True),
        ("FileVault", True),
        ("HomeButtonSensitivity", True),
        ("iCloudDiagnostics", True),
        ("iCloudStorage", True),
        ("iMessageAndFaceTime", True),
        ("Location", False),  # messes with NTP and other things?
        ("MessagingActivationUsingPhoneNumber", True),
        ("OnBoarding", True),
        ("Passcode", True),
        ("Payment", True),
        ("Privacy", True),
        ("Restore", True),
        ("RestoreCompleted", True),
        ("ScreenSaver", True),
        ("ScreenTime", True),
        ("SIMSetup", True),
        ("Siri", True),
        ("SoftwareUpdate", True),
        ("TapToSetup", True),
        ("TOS", True),
        ("TVHomeScreenSync", True),
        ("TVProviderSignIn", True),
        ("TVRoom", True),
        ("UpdateCompleted", True),
        ("WatchMigration", True),
        ("Welcome", True),
        ("Zoom", True),
    )
    SKIPPABLE_SETUP_PANE_CHOICES = [(name, name) for name, __ in SKIPPABLE_SETUP_PANES]

    # link with the Apple DEP web services
    uuid = models.UUIDField(unique=True, editable=False)
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE)

    # to protect the dep enrollment endpoint. Link to the meta business unit too
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="dep_enrollment", editable=False)

    # Authentication

    # if linked to a realm, a user has to authenticate to get the mdm payload.
    # if realm, use the realm user either to auto populate the user form
    # or auto create the admin
    use_realm_user = models.BooleanField(default=False)
    # if the realm user is not an admin, we will only use the info
    # to autopopulate the user form, and we will need a default admin
    realm_user_is_admin = models.BooleanField(default=True)
    # optional admin account info
    admin_full_name = models.CharField(max_length=80, blank=True, null=True)
    admin_short_name = models.CharField(max_length=32, blank=True, null=True)
    admin_password_hash = models.JSONField(null=True, editable=False)

    # standard DEP profile configuration

    # https://developer.apple.com/documentation/devicemanagement/profile
    name = models.CharField(max_length=125, unique=True)  # see CONFIG_NAME_INVALID error
    allow_pairing = models.BooleanField(default=False)  # deprecated in iOS 13
    auto_advance_setup = models.BooleanField(default=False)
    await_device_configured = models.BooleanField(default=False)
    # configuration_web_url is automatically set for authentication or direct MDM payload download
    department = models.CharField(max_length=125, blank=True)  # see DEPARTMENT_INVALID error
    # devices see DEPDevice
    is_mandatory = models.BooleanField(default=True)
    is_mdm_removable = models.BooleanField(default=False)  # can be set to False only if is_supervised is True
    is_multi_user = models.BooleanField(default=True)
    is_supervised = models.BooleanField(default=True)  # deprecated
    language = models.CharField(max_length=3, choices=ISO_639_1_CHOICES, blank=True)
    org_magic = models.CharField(max_length=256, blank=True)  # see MAGIC_INVALID error
    region = models.CharField(max_length=2, choices=ISO_3166_1_ALPHA_2_CHOICES, blank=True)
    skip_setup_items = ArrayField(models.CharField(max_length=64,
                                                   choices=SKIPPABLE_SETUP_PANE_CHOICES),
                                  editable=False)
    # TODO: supervising_host_certs
    support_email_address = models.EmailField(max_length=250, blank=True)  # see SUPPORT_EMAIL_INVALID error
    support_phone_number = models.CharField(max_length=50, blank=True)  # see SUPPORT_PHONE_INVALID error
    # url is automatically set using the enrollment secret
    # Auto populate anchor_certs using the fullchain when building the profile payload?
    include_tls_certificates = models.BooleanField(default=False)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_enrollment", args=(self.pk,))

    def assigned_devices(self):
        return self.depdevice_set.exclude(last_op_type=DEPDevice.OP_TYPE_DELETED)

    def serialize_for_event(self):
        return {"dep_enrollment": {"uuid": self.pk,
                                   "name": self.name,
                                   "created_at": self.created_at,
                                   "updated_at": self.updated_at}}

    def requires_account_configuration(self):
        return self.use_realm_user or (self.admin_full_name and self.admin_short_name and self.admin_password_hash)


class DEPDevice(models.Model):
    PROFILE_STATUS_EMPTY = "empty"
    PROFILE_STATUS_ASSIGNED = "assigned"
    PROFILE_STATUS_PUSHED = "pushed"
    PROFILE_STATUS_REMOVED = "removed"
    PROFILE_STATUS_CHOICES = (
        (PROFILE_STATUS_EMPTY, "Empty"),
        (PROFILE_STATUS_ASSIGNED, "Assigned"),
        (PROFILE_STATUS_PUSHED, "Pushed"),
        (PROFILE_STATUS_REMOVED, "Removed"),
    )

    OP_TYPE_ADDED = "added"
    OP_TYPE_MODIFIED = "modified"
    OP_TYPE_DELETED = "deleted"
    OP_TYPE_CHOICES = (
        (OP_TYPE_ADDED, "Added"),
        (OP_TYPE_MODIFIED, "Modified"),
        (OP_TYPE_DELETED, "Deleted"),
    )

    # link with the Apple DEP web services
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE, editable=False)
    serial_number = models.TextField(unique=True)

    # ABM info
    # assignment
    device_assigned_by = models.EmailField(editable=False)
    device_assigned_date = models.DateTimeField(editable=False)
    # sync service
    last_op_type = models.CharField(max_length=64, choices=OP_TYPE_CHOICES, null=True, editable=False)
    last_op_date = models.DateTimeField(null=True, editable=False)
    # profile
    profile_status = models.CharField(max_length=64,
                                      choices=PROFILE_STATUS_CHOICES,
                                      default=PROFILE_STATUS_EMPTY,
                                      editable=False)
    profile_uuid = models.UUIDField(null=True, editable=False)
    profile_assign_time = models.DateTimeField(null=True, editable=False)
    profile_push_time = models.DateTimeField(null=True, editable=False)

    # Zentral enrollment/profile
    enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.PROTECT, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("serial_number",)

    def __str__(self):
        return self.serial_number

    def get_absolute_url(self):
        return "{}#{}".format(self.virtual_server.get_absolute_url(), self.serial_number)

    def is_deleted(self):
        return self.last_op_type == self.OP_TYPE_DELETED


class DEPEnrollmentSessionManager(models.Manager):
    def create_from_dep_enrollment(self, dep_enrollment, serial_number, udid, commit=True):
        # Build a new secret, only for one enrollment, only for this machine
        # scep server.

        enrollment_secret = dep_enrollment.enrollment_secret

        meta_business_unit = enrollment_secret.meta_business_unit
        tags = list(enrollment_secret.tags.all())

        # verified only once with the SCEP payload
        quota = 1

        # expires 60 minutes from now, plenty enough for the device to contact the SCEP server
        expired_at = timezone.now() + timedelta(hours=1)

        new_es = EnrollmentSecret(
            meta_business_unit=meta_business_unit,
            serial_numbers=[serial_number],
            udids=[udid],
            quota=quota,
            expired_at=expired_at,
        )
        new_es.save(secret_length=56)  # CN max 64 - $ separator - prefix MDM$DEP
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.STARTED,
                                        dep_enrollment=dep_enrollment,
                                        enrollment_secret=new_es)
        if commit:
            enrollment_session.save()
        return enrollment_session


class DEPEnrollmentSession(EnrollmentSession):
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    dep_enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="dep_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    objects = DEPEnrollmentSessionManager()

    def get_enrollment(self):
        return self.dep_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$DEP"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("dep", self.dep_enrollment.serialize_for_event())

    def get_blueprint(self):
        return self.dep_enrollment.blueprint

    # status update methods

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None
                and not self.enrolled_device)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.dep_enrollment.scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.dep_enrollment.scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# User Enrollment


class UserEnrollment(MDMEnrollment):
    name = models.CharField(max_length=256, unique=True)

    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="user_enrollment")
    # if linked to a realm, the enrollment can start from the device

    class Meta:
        ordering = ("-created_at",)

    def __str__(self):
        return self.name

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "name": self.name,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"user_enrollment": d}

    def get_absolute_url(self):
        return reverse("mdm:user_enrollment", args=(self.pk,))

    def get_enroll_full_url(self):
        return "https://{}{}".format(
            settings["api"]["fqdn"],
            reverse("mdm:user_enrollment_enroll", args=(self.pk,))
        )

    def get_service_discovery_full_url(self):
        if self.realm:
            return "https://{}{}".format(
                settings["api"]["fqdn"],
                reverse("mdm:user_enrollment_service_discovery", args=(self.enrollment_secret.secret,))
            )

    def revoke(self):
        if not self.enrollment_secret.revoked_at:
            # TODO events
            self.enrollment_secret.revoked_at = timezone.now()
            self.enrollment_secret.save()
            self.save()


class UserEnrollmentSessionManager(models.Manager):
    def create_from_user_enrollment(self, user_enrollment, managed_apple_id=None):
        if managed_apple_id:
            status = self.model.STARTED
            quota = 1  # verified once with SCEP
        else:
            status = self.model.ACCOUNT_DRIVEN_START
            quota = 10  # verified at the beginning of the authentication and once with SCEP
        enrollment_secret = user_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            quota=quota,
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=55)  # CN max 64 - $ separator - mdm$user
        new_es.tags.set(tags)
        enrollment_session = self.model(status=status,
                                        user_enrollment=user_enrollment,
                                        managed_apple_id=managed_apple_id,
                                        enrollment_secret=new_es)
        enrollment_session.save()
        return enrollment_session


class UserEnrollmentSession(EnrollmentSession):
    ACCOUNT_DRIVEN_START = "ACCOUNT_DRIVEN_START"
    ACCOUNT_DRIVEN_AUTHENTICATED = "ACCOUNT_DRIVEN_AUTHENTICATED"
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (ACCOUNT_DRIVEN_START, _("Account-based onboarding initiated")),
        (ACCOUNT_DRIVEN_AUTHENTICATED, _("Account-based onboarding authenticated")),
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    user_enrollment = models.ForeignKey(UserEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="user_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    managed_apple_id = models.EmailField(null=True)
    access_token = models.CharField(max_length=40, unique=True, null=True)

    objects = UserEnrollmentSessionManager()

    def get_enrollment(self):
        return self.user_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$USER"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("user", self.user_enrollment.serialize_for_event())

    def get_blueprint(self):
        return self.user_enrollment.blueprint

    # status update methods

    def set_account_driven_authenticated_status(self, realm_user):
        test = (realm_user
                and realm_user.email
                and self.status == self.ACCOUNT_DRIVEN_START)
        self._set_next_status(self.ACCOUNT_DRIVEN_AUTHENTICATED, test,
                              realm_user=realm_user,
                              managed_apple_id=realm_user.email,
                              access_token=get_random_string(40))

    def set_started_status(self):
        test = (self.realm_user
                and self.managed_apple_id
                and self.access_token
                and self.status == self.ACCOUNT_DRIVEN_AUTHENTICATED)
        self._set_next_status(self.STARTED, test)

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None
                and not self.enrolled_device)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.user_enrollment.scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.user_enrollment.scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# MDM re-enrollment


class ReEnrollmentSessionManager(models.Manager):
    def create_from_enrollment_session(self, enrollment_session):
        if not enrollment_session.enrolled_device:
            raise ValueError("The enrollment session doesn't have an enrolled device")
        enrollment = enrollment_session.get_enrollment()
        enrollment_secret = enrollment.enrollment_secret

        meta_business_unit = enrollment_secret.meta_business_unit
        tags = list(enrollment_secret.tags.all())

        # verified only once with the SCEP payload
        quota = 1

        # expires 60 minutes from now, plenty enough for the device to contact the SCEP server
        expired_at = timezone.now() + timedelta(hours=1)

        enrolled_device = enrollment_session.enrolled_device
        new_es = EnrollmentSecret(
            meta_business_unit=meta_business_unit,
            serial_numbers=[enrolled_device.serial_number],
            udids=[enrolled_device.udid],
            quota=quota,
            expired_at=expired_at,
        )
        new_es.save(secret_length=57)  # CN max 64 - $ separator - prefix MDM$RE
        new_es.tags.set(tags)
        enrollment_session = self.model(status=self.model.STARTED,
                                        enrollment_secret=new_es,
                                        enrolled_device=enrolled_device,  # important, see _reenroll !!
                                        realm_user=enrollment_session.realm_user)
        if isinstance(enrollment, DEPEnrollment):
            enrollment_session.dep_enrollment = enrollment
        elif isinstance(enrollment, OTAEnrollment):
            enrollment_session.ota_enrollment = enrollment
        elif isinstance(enrollment, UserEnrollment):
            enrollment_session.user_enrollment = enrollment
        else:
            raise ValueError("Unknown enrollment type")
        enrollment_session.save()
        return enrollment_session


class ReEnrollmentSession(EnrollmentSession):
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),  # Optional, the SCEP service verified the MDM CSR
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    dep_enrollment = models.ForeignKey(DEPEnrollment, on_delete=models.CASCADE, null=True)
    ota_enrollment = models.ForeignKey(OTAEnrollment, on_delete=models.CASCADE, null=True)
    user_enrollment = models.ForeignKey(UserEnrollment, on_delete=models.CASCADE, null=True)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="reenrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    objects = ReEnrollmentSessionManager()

    def get_enrollment(self):
        if self.dep_enrollment:
            return self.dep_enrollment
        elif self.ota_enrollment:
            return self.ota_enrollment
        else:
            return self.user_enrollment

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$RE"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("re", self.get_enrollment().serialize_for_event())

    def get_blueprint(self):
        return self.get_enrollment().blueprint

    # status update methods

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        if self.get_enrollment().scep_verification:
            allowed_statuses = (self.SCEP_VERIFIED,)
            scep_ok = self.scep_request is not None
        else:
            allowed_statuses = (self.STARTED, self.SCEP_VERIFIED)
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status in allowed_statuses
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        if self.get_enrollment().scep_verification:
            scep_ok = self.scep_request is not None
        else:
            scep_ok = True
        test = (enrolled_device
                and scep_ok
                and self.status == self.AUTHENTICATED
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# Artifacts


class ArtifactType(enum.Enum):
    EnterpriseApp = "Enterprise App"
    Profile = "Profile"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)


class ArtifactOperation(enum.Enum):
    Installation = "Installation"
    Removal = "Removal"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.value) for i in cls)


class Artifact(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=256, unique=True)
    type = models.CharField(max_length=64, choices=ArtifactType.choices(), editable=False)
    channel = models.CharField(max_length=64, choices=Channel.choices(), editable=False)
    platforms = ArrayField(models.CharField(max_length=64, choices=Platform.choices()), default=Platform.all_values)

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    trashed_at = models.DateTimeField(null=True, editable=False)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:artifact", args=(self.pk,))


class BlueprintArtifact(models.Model):
    blueprint = models.ForeignKey(Blueprint, on_delete=models.CASCADE)
    artifact = models.ForeignKey(Artifact, on_delete=models.CASCADE)
    install_before_setup_assistant = models.BooleanField(default=False)
    auto_update = models.BooleanField(default=True)
    priority = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    def get_absolute_url(self):
        return "{}#ba-{}".format(self.artifact.get_absolute_url(), self.pk)


class ArtifactVersionManager(models.Manager):
    def _next_to(self, target, select, artifact_operation, fetch_all=False):
        if isinstance(target, EnrolledDevice):
            enrolled_device = target
            channel = Channel.Device
            command_table = "mdm_devicecommand"
            target_table = "mdm_deviceartifact"
            target_attr = "enrolled_device_id"
        elif isinstance(target, EnrolledUser):
            enrolled_device = target.enrolled_device
            channel = Channel.User
            command_table = "mdm_usercommand"
            target_table = "mdm_userartifact"
            target_attr = "enrolled_user_id"
        else:
            raise ValueError("Target must be an EnrolledDevice or an EnrolledUser")

        blueprint = enrolled_device.blueprint
        if blueprint is None and artifact_operation == ArtifactOperation.Installation:
            return

        # Sorry… use -1 as blueprint pk when no blueprint is configured
        # will return 0 blueprint artifact versions
        # used to remove all installed artifact versions
        args = [channel.name, enrolled_device.platform, blueprint.pk if blueprint else -1]
        ba_where_list = ["a.channel = %s", "%s = ANY(a.platforms)", "ba.blueprint_id = %s"]
        if enrolled_device.awaiting_configuration:
            args.append(True)
            ba_where_list.append("ba.install_before_setup_assistant = %s")
        ba_wheres = " and ".join(ba_where_list)
        args.extend([target.pk, target.pk, artifact_operation.name])
        query = (
            "with all_blueprint_artifact_versions as ("  # All blueprint artifact versions, ranked by version
            "  select av.id, av.version, av.artifact_id, av.created_at,"
            "  rank() over (partition by av.artifact_id order by version desc) rank,"
            "  ba.auto_update, ba.priority"
            "  from mdm_artifactversion as av"
            "  join mdm_artifact as a on (a.id = av.artifact_id)"
            "  join mdm_blueprintartifact as ba on (ba.artifact_id = a.id)"
            f"  where {ba_wheres}"
            "), blueprint_artifact_versions as ("  # Keep only the latest versions of each artifact
            "  select id, version, created_at, artifact_id, auto_update, priority"
            "  from all_blueprint_artifact_versions"
            "  where rank=1"
            "), all_target_artifact_versions as ("  # All the artifact versions installed on the target
            "  select av.id, av.version, av.artifact_id, av.created_at,"
            "  rank() over (partition by av.artifact_id order by version desc) rank"
            "  from mdm_artifactversion as av"
            f"  join {target_table} as ta on (ta.artifact_version_id = av.id)"
            f"  where ta.{target_attr} = %s"
            "), target_artifact_versions as ("  # Keep only the latest versions of each target artifact
            "  select id, version, artifact_id, created_at"
            "  from all_target_artifact_versions"
            "  where rank=1"
            "), failed_artifact_version_operations as ("  # All the artifact versions with failed operations
            "  select distinct artifact_version_id as id"
            f"  from {command_table}"
            f"  where {target_attr} = %s and artifact_operation = %s and status = 'Error'"
            f") {select}"
        )
        if not fetch_all:
            query += " limit 1"

        cursor = connection.cursor()
        cursor.execute(query, args)
        pk_list = [t[0] for t in cursor.fetchall()]
        qs = self.select_related("artifact", "profile", "enterprise_app")
        if fetch_all:
            artifact_version_list = list(qs.filter(pk__in=pk_list))
            artifact_version_list.sort(key=lambda artifact_version: pk_list.index(artifact_version.pk))
            return artifact_version_list
        else:
            if pk_list:
                return qs.get(pk=pk_list[0])

    def next_to_install(self, target, fetch_all=False):
        select = (
            # Present in the blueprint
            "select bav.id from blueprint_artifact_versions as bav "
            "left join failed_artifact_version_operations as favo on (favo.id = bav.id) "
            "left join target_artifact_versions as tav on (tav.artifact_id = bav.artifact_id) "
            # - No previous installation error AND
            #   - Not installed on the target OR
            #   - Installed but with a different version, if auto update is true
            # if auto update is false, a more recent version will not be installed.
            # The version number is not used, because different artifact versions of the same artifact
            # can end up having the same version number.
            "where favo.id is null and (tav.id is null or (bav.id <> tav.id and bav.auto_update)) "
            "order by bav.priority desc, bav.created_at asc"
        )
        return self._next_to(target, select, ArtifactOperation.Installation, fetch_all=fetch_all)

    def next_to_remove(self, target, fetch_all=False):
        select = (
            # Installed on the target
            "select tav.id from target_artifact_versions as tav "
            "left join mdm_artifact as a on (tav.artifact_id = a.id) "
            "left join failed_artifact_version_operations as favo on (favo.id = tav.id) "
            "left join blueprint_artifact_versions as bav on (bav.artifact_id = tav.artifact_id) "
            # - Only Profiles
            # - No previous removal error AND
            # - Not present in the blueprint
            "where a.type = 'Profile' and favo.id is null and bav.id is null "
            "order by tav.created_at asc"
        )
        return self._next_to(target, select, ArtifactOperation.Removal, fetch_all=fetch_all)

    def latest_for_blueprint(self, blueprint, artifact_type=None):
        ba_where_list = ["ba.blueprint_id = %s"]
        args = [blueprint.pk]
        if artifact_type:
            ba_where_list.append("a.type = %s")
            args.append(artifact_type.name)
        ba_wheres = " and ".join(ba_where_list)
        query = (
            "with all_blueprint_artifact_versions as ("  # All blueprint artifact versions, ranked by version
            "  select av.artifact_id, av.id,"
            "  rank() over (partition by av.artifact_id order by version desc) rank"
            "  from mdm_artifactversion as av"
            "  join mdm_artifact as a on (a.id = av.artifact_id)"
            "  join mdm_blueprintartifact as ba on (ba.artifact_id = a.id)"
            f"  where {ba_wheres}"
            ") select artifact_id, id "
            "from all_blueprint_artifact_versions "
            "where rank=1"
        )
        cursor = connection.cursor()
        cursor.execute(query, args)
        return cursor.fetchall()


class ArtifactVersion(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    artifact = models.ForeignKey(Artifact, on_delete=models.CASCADE)
    version = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)

    objects = ArtifactVersionManager()

    def __str__(self):
        return f"{self.artifact} v{self.version}"

    def get_absolute_url(self):
        return "{}#{}".format(self.artifact.get_absolute_url(), self.pk)

    class Meta:
        unique_together = (("artifact", "version"),)


class Profile(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="profile", on_delete=models.CASCADE)
    source = models.BinaryField()
    filename = models.TextField()
    payload_identifier = models.TextField(db_index=True)
    payload_uuid = models.TextField()
    payload_display_name = models.TextField()
    payload_description = models.TextField()

    def __str__(self):
        return self.payload_display_name

    @cached_property
    def payloads(self):
        return [
            (payload.get("PayloadType"), payload.get("PayloadDisplayName"))
            for payload in plistlib.loads(self.source).get("PayloadContent", [])
        ]

    def get_payload_description(self):
        return plistlib.loads(self.source).get("PayloadDescription")

    def installed_payload_identifier(self):
        return get_payload_identifier("artifact", self.artifact_version.artifact.pk)

    def installed_payload_uuid(self):
        return str(self.artifact_version.pk).upper()


def enterprise_application_package_path(instance, filename):
    return f"mdm/enterprise_apps/{instance.artifact_version.artifact.pk}/{instance.artifact_version.pk}.pkg"


class EnterpriseApp(models.Model):
    artifact_version = models.OneToOneField(ArtifactVersion, related_name="enterprise_app", on_delete=models.CASCADE)
    package = models.FileField(upload_to=enterprise_application_package_path)
    filename = models.TextField()
    product_id = models.TextField()
    product_version = models.TextField()
    bundles = models.JSONField(default=list)
    manifest = models.JSONField()

    def __str__(self):
        return f"{self.product_id} {self.product_version}"

    class Meta:
        indexes = [models.Index(fields=["product_id", "product_version"])]


class TargetArtifactStatus(enum.Enum):
    Acknowledged = "Acknowledged"
    AwaitingConfirmation = "Awaiting confirmation"
    Installed = "Installed"

    @classmethod
    def choices(cls):
        return tuple((i.name, i.name) for i in cls)


class TargetArtifact(models.Model):
    artifact_version = models.ForeignKey(ArtifactVersion, on_delete=models.PROTECT)
    status = models.CharField(
        max_length=64,
        choices=TargetArtifactStatus.choices(),
        default=TargetArtifactStatus.Acknowledged.name
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class DeviceArtifact(TargetArtifact):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, related_name="installed_artifacts")

    class Meta:
        unique_together = ("enrolled_device", "artifact_version")


class UserArtifact(TargetArtifact):
    enrolled_user = models.ForeignKey(EnrolledUser, on_delete=models.CASCADE, related_name="installed_artifacts")

    class Meta:
        unique_together = ("enrolled_user", "artifact_version")


# Commands


class CommandStatus(enum.Enum):
    Acknowledged = "Acknowledged"
    Error = "Error"
    CommandFormatError = "CommandFormatError"
    NotNow = "NotNow"

    @classmethod
    def choices(cls):
        return tuple((i.value[0], i.value[0]) for i in cls)


class Command(models.Model):
    uuid = models.UUIDField(unique=True, editable=False)

    name = models.CharField(max_length=128)
    artifact_version = models.ForeignKey(ArtifactVersion, on_delete=models.PROTECT, null=True)
    artifact_operation = models.CharField(max_length=64, choices=ArtifactOperation.choices(), null=True)
    kwargs = models.JSONField(default=dict)

    not_before = models.DateTimeField(null=True)
    time = models.DateTimeField(null=True)  # no time => queued
    result = models.BinaryField(null=True)  # to store the result of some commands
    result_time = models.DateTimeField(null=True)
    status = models.CharField(max_length=64, choices=CommandStatus.choices(), null=True)
    error_chain = models.JSONField(null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return " - ".join(s for s in (self.name, str(self.uuid), self.status) if s)

    class Meta:
        abstract = True


class DeviceCommand(Command):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, related_name="commands")


class UserCommand(Command):
    enrolled_user = models.ForeignKey(EnrolledUser, on_delete=models.CASCADE, related_name="commands")
