import base64
from datetime import timedelta
import logging
import uuid
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.contrib.postgres.fields import ArrayField, JSONField
from django.core.exceptions import ObjectDoesNotExist
from django.db import models
from django.db.models import F
from django.urls import reverse
from django.utils import timezone
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from realms.models import Realm, RealmUser
from zentral.conf import settings
from zentral.contrib.inventory.models import EnrollmentSecret, EnrollmentSecretRequest, MetaBusinessUnit, MetaMachine
from zentral.utils.osx_package import get_standalone_package_builders
from .exceptions import EnrollmentSessionStatusError
from .utils import build_mdm_enrollment_package


logger = logging.getLogger("zentral.contrib.mdm.models")


# Push certificates


class PushCertificate(models.Model):
    name = models.CharField(max_length=256, unique=True)
    topic = models.CharField(max_length=256, unique=True)
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()
    certificate = models.BinaryField()
    private_key = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ('name', 'topic')

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:push_certificate", args=(self.pk,))


# MetaBusinessUnit n <-> 1 PushCertificate
# Should be a ForeignKey on MetaBusinessUnit, but we don't want to introduce a dependency.
# MetaBusinessUnitPushCertificate defines, for each MetaBusinessUnit, the corresponding PushCertificate


class MetaBusinessUnitPushCertificate(models.Model):
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.CASCADE)
    meta_business_unit = models.OneToOneField(MetaBusinessUnit, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)


# Enrollment


class EnrolledDeviceManager(models.Manager):
    def active_in_mbu(self, meta_business_unit):
        try:
            push_certificate = meta_business_unit.metabusinessunitpushcertificate.push_certificate
        except ObjectDoesNotExist:
            return self.none()
        return self.filter(checkout_at__isnull=True,
                           token__isnull=False,
                           push_magic__isnull=False,
                           push_certificate=push_certificate)


class EnrolledDevice(models.Model):
    enrollment_id = models.TextField(null=True)
    awaiting_configuration = models.BooleanField(null=True)

    # device info
    serial_number = models.TextField(db_index=True)
    udid = models.CharField(max_length=36, unique=True)

    # push
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.CASCADE)
    token = models.BinaryField(blank=True, null=True)
    push_magic = models.TextField(blank=True, null=True)

    # unlock token
    unlock_token = models.BinaryField(blank=True, null=True)

    # timestamps
    checkout_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrolledDeviceManager()

    def purge_state(self):
        self.installeddeviceartifact_set.all().delete()
        self.devicecommand_set.all().delete()

    def do_checkout(self):
        self.token = self.push_magic = self.unlock_token = None
        self.checkout_at = timezone.now()
        self.purge_state()
        self.save()

    def can_be_poked(self):
        return self.checkout_at is None and self.token is not None and self.push_magic is not None


class EnrolledUser(models.Model):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)
    enrollment_id = models.TextField(null=True)

    # user info
    user_id = models.CharField(max_length=36, unique=True)
    long_name = models.TextField()
    short_name = models.TextField()

    # push
    token = models.BinaryField()

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# Common base model for the OTA and DEP enrollment sessions


class EnrollmentSession(models.Model):
    product = models.TextField()
    version = models.TextField()
    imei = models.CharField(max_length=18, null=True)
    meid = models.CharField(max_length=18, null=True)
    language = models.CharField(max_length=64, null=True)

    realm_user = models.ForeignKey(RealmUser, on_delete=models.PROTECT, blank=True, null=True)

    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True

    def update_with_payload(self, payload, commit=True):
        for attr in ("product", "version", "imei", "meid", "language"):
            val = payload.get(attr.upper(), None)
            if val:
                field = self._meta.get_field(attr)
                field_max_length = getattr(field, "max_length", None)
                if field_max_length and len(val) > field_max_length:
                    logger.error("Value %s for field %s too long. Will be truncated.", val, attr)
                    val = val[:field_max_length]
                setattr(self, attr, val)
        if commit:
            self.save()

    def get_common_name(self):
        return "{prefix}${secret}".format(prefix=self.get_prefix(),
                                          secret=self.enrollment_secret.secret)

    def get_organization(self):
        return "MBU${}".format(self.enrollment_secret.meta_business_unit.pk)

    def get_serial_number(self):
        return self.enrollment_secret.serial_numbers[0]

    def get_urlsafe_serial_number(self):
        return MetaMachine(self.get_serial_number()).get_urlsafe_serial_number()

    def get_challenge(self):
        path = reverse("mdm:verify_scep_csr")
        return base64.b64encode(path.encode("utf-8")).decode("ascii")

    def get_payload_name(self):
        return "Zentral - {prefix} Enrollment SCEP".format(prefix=" - ".join(self.get_prefix().split("$")))

    def is_completed(self):
        return self.status == self.COMPLETED

    def serialize_for_event(self, enrollment_session_type, extra_dict):
        d = {"pk": self.pk,
             "type": enrollment_session_type,
             "status": self.status,
             "product": self.product,
             "version": self.version,
             "language": self.language,
             "enrollment_secret": self.enrollment_secret.serialize_for_event(),
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        if self.imei:
            d["imei"] = self.imei
        if self.meid:
            d["meid"] = self.meid
        d.update(extra_dict)
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


# OTA Enrollment


class OTAEnrollment(models.Model):
    name = models.CharField(max_length=256, unique=True)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="ota_enrollment")
    # linked to an auth realm
    # if linked, a user has to authenticate to get the mdm payload.
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT, blank=True, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

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
        return reverse("mdm:ota_enrollment", args=(self.enrollment_secret.meta_business_unit.pk, self.pk))

    def get_enroll_full_url(self):
        if self.realm:
            path = reverse("mdm:ota_enrollment_enroll", args=(self.enrollment_secret.meta_business_unit.pk, self.pk))
            return "{}{}".format(settings["api"]["tls_hostname"], path)

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

    def create_from_machine_info(self, ota_enrollment, serial_number, udid, payload):
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
        enrollment_session = self.model(status=self.model.PHASE_2,
                                        ota_enrollment=ota_enrollment,
                                        enrollment_secret=new_es)
        enrollment_session.update_with_payload(payload)
        return enrollment_session


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

    def get_prefix(self):
        if self.status == self.PHASE_2:
            return "OTA"
        elif self.status == self.PHASE_3:
            return "MDM$OTA"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("ota", self.ota_enrollment.serialize_for_event())

    # status update methods

    def set_phase2_status(self, es_request, serial_number, udid, payload):
        test = (serial_number
                and udid
                and payload
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
        # save the current machine info
        self.update_with_payload(payload)

    def set_phase2_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.PHASE_2
                and not self.phase2_scep_request
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_2_SCEP_VERIFIED, test, phase2_scep_request=es_request)

    def set_phase3_status(self):
        test = (self.status == self.PHASE_2_SCEP_VERIFIED
                and self.phase2_scep_request is not None
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_3, test)

    def set_phase3_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.PHASE_3
                and self.phase2_scep_request is not None
                and not self.phase3_scep_request
                and not self.enrolled_device)
        self._set_next_status(self.PHASE_3_SCEP_VERIFIED, test, phase3_scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        test = (enrolled_device
                and self.status == self.PHASE_3_SCEP_VERIFIED
                and self.phase2_scep_request is not None
                and self.phase3_scep_request is not None
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        test = (enrolled_device
                and self.status == self.AUTHENTICATED
                and self.phase2_scep_request is not None
                and self.phase3_scep_request is not None
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
        return "\n".join(l for l in (l.strip() for l in self.address.split(",")) if l)


class DEPToken(models.Model):
    certificate = models.BinaryField(editable=False)
    private_key = models.BinaryField(editable=False)

    consumer_key = models.CharField(max_length=128, null=True, editable=False)
    consumer_secret = models.CharField(max_length=128, null=True, editable=False)
    access_token = models.CharField(max_length=128, null=True, editable=False)
    access_secret = models.CharField(max_length=128, null=True, editable=False)
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


class DEPProfile(models.Model):
    SKIPPABLE_SETUP_PANES = (
        ("AppleID", True),
        ("Biometric", False),
        ("Diagnostics", True),
        ("DisplayTone", True),
        ("Location", False),  # messes with NTP and other things?
        ("Passcode", True),
        ("Payment", True),
        ("Privacy", True),
        ("Restore", True),
        ("Siri", True),
        ("TOS", True),
        ("Zoom", True),
        ("Android", True),
        ("Appearance", True),
        ("HomeButtonSensitivity", True),
        ("iMessageAndFaceTime", True),
        ("OnBoarding", True),
        ("ScreenTime", True),
        ("SoftwareUpdate", True),
        ("WatchMigration", True),
        ("FileVault", True),
        ("iCloudDiagnostics", True),
        ("iCloudStorage", True),
        ("Registration", True),
        ("ScreenSaver", True),
        ("TapToSetup", True),
        ("TVHomeScreenSync", True),
        ("TVProviderSignIn", True),
        ("TVRoom", True),
    )
    SKIPPABLE_SETUP_PANE_CHOICES = [(name, name) for name, __ in SKIPPABLE_SETUP_PANES]

    # link with the Apple DEP web services
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE)
    uuid = models.UUIDField(unique=True, editable=False)

    # linked to an auth realm
    # if linked, a user has to authenticate to get the mdm payload.
    realm = models.ForeignKey(Realm, on_delete=models.PROTECT, blank=True, null=True)

    # if realm, use the realm user either to auto populate the user form
    # or auto create the admin
    use_realm_user = models.BooleanField(default=False)

    # if the realm user is not an admin, we will only use the info
    # to autopopulate the user form, and we will need a default admin
    realm_user_is_admin = models.BooleanField(default=True)

    # optional admin account info
    admin_full_name = models.CharField(max_length=80, blank=True, null=True)
    admin_short_name = models.CharField(max_length=32, blank=True, null=True)
    admin_password_hash = JSONField(null=True, editable=False)

    # standard DEP profile configuration
    name = models.CharField(max_length=125, unique=True)  # see CONFIG_NAME_INVALID error
    allow_pairing = models.BooleanField(default=False)
    is_supervised = models.BooleanField(default=True)
    # cf doc: Only available for Apple School Manager
    # is_multi_user = models.BooleanField(default=True)
    is_mandatory = models.BooleanField(default=True)
    await_device_configured = models.BooleanField(default=False)
    auto_advance_setup = models.BooleanField(default=False)
    is_mdm_removable = models.BooleanField(default=False)  # can be set to False only if is_supervised is True
    skip_setup_items = ArrayField(models.CharField(max_length=64,
                                                   choices=SKIPPABLE_SETUP_PANE_CHOICES),
                                  editable=False)
    support_phone_number = models.CharField(max_length=50, blank=True)  # see SUPPORT_PHONE_INVALID error
    support_email_address = models.EmailField(max_length=250, blank=True)  # see SUPPORT_EMAIL_INVALID error
    org_magic = models.CharField(max_length=256, blank=True)  # see MAGIC_INVALID error
    department = models.CharField(max_length=125, blank=True)  # see DEPARTMENT_INVALID error
    # TODO: supervising_host_certs
    # Auto populate anchor_certs the fullchain when building the profile payload?
    include_tls_certificates = models.BooleanField(default=False)
    # devices, does not apply
    # TODO: language, region

    # to protect the dep enrollment endpoint. Link to the meta business unit too
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="dep_profile", editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_profile", args=(self.enrollment_secret.meta_business_unit.pk, self.pk))

    def assigned_devices(self):
        return self.depdevice_set.exclude(last_op_type=DEPDevice.OP_TYPE_DELETED)

    def get_meta_business_unit(self):
        return self.enrollment_secret.meta_business_unit

    def serialize_for_event(self):
        return {"dep_profile": {"pk": self.pk,
                                "uuid": str(self.uuid),
                                "name": self.name,
                                "created_at": self.created_at,
                                "updated_at": self.updated_at}}


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

    # our profile
    profile = models.ForeignKey(DEPProfile, on_delete=models.PROTECT, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("serial_number",)

    def __str__(self):
        return self.serial_number

    def get_absolute_url(self):
        return "{}#dep_device".format(
            reverse("mdm:device",
                    args=(MetaMachine(self.serial_number).get_urlsafe_serial_number(),))
        )

    def is_deleted(self):
        return self.last_op_type == self.OP_TYPE_DELETED


class DEPEnrollmentSessionManager(models.Manager):
    def create_from_dep_profile(self, dep_profile, serial_number, udid, payload, commit=False):
        # Build a new secret, only for one enrollment, only for this machine
        # scep server.

        enrollment_secret = dep_profile.enrollment_secret

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
                                        dep_profile=dep_profile,
                                        enrollment_secret=new_es)
        enrollment_session.update_with_payload(payload, commit=commit)
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
    dep_profile = models.ForeignKey(DEPProfile, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="dep_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")

    objects = DEPEnrollmentSessionManager()

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$DEP"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        return super().serialize_for_event("dep", self.dep_profile.serialize_for_event())

    # status update methods

    def set_scep_verified_status(self, es_request):
        test = (es_request
                and self.status == self.STARTED
                and self.scep_request is None
                and not self.enrolled_device)
        self._set_next_status(self.SCEP_VERIFIED, test, scep_request=es_request)

    def set_authenticated_status(self, enrolled_device):
        test = (enrolled_device
                and self.status == self.SCEP_VERIFIED
                and self.scep_request is not None
                and not self.enrolled_device)
        self._set_next_status(self.AUTHENTICATED, test, enrolled_device=enrolled_device)

    def set_completed_status(self, enrolled_device):
        test = (enrolled_device
                and self.status == self.AUTHENTICATED
                and self.scep_request is not None
                and self.enrolled_device == enrolled_device)
        self._set_next_status(self.COMPLETED, test)


# MDM commands


class DeviceCommand(models.Model):
    STATUS_CODE_ACKNOWLEDGED = "Acknowledged"
    STATUS_CODE_ERROR = "Error"
    STATUS_CODE_COMMAND_FORMAT_ERROR = "CommandFormatError"
    STATUS_CODE_NOT_NOW = "NotNow"
    STATUS_CODE_CHOICES = (
        (STATUS_CODE_ACKNOWLEDGED, "Acknowledged"),
        (STATUS_CODE_ERROR, "Error"),
        (STATUS_CODE_COMMAND_FORMAT_ERROR, "Command format error"),
        (STATUS_CODE_NOT_NOW, "Not now"),
    )

    # enrolled_device
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)

    # command
    uuid = models.UUIDField(unique=True, default=uuid.uuid4)
    request_type = models.CharField(max_length=128)
    body = models.TextField()

    time = models.DateTimeField(null=True)  # no time => queued
    result_time = models.DateTimeField(null=True)
    status_code = models.CharField(max_length=64, choices=STATUS_CODE_CHOICES, null=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return " - ".join(s for s in (self.request_type, str(self.uuid), self.status_code) if s)


# MDM artifacts


class BaseArtifact(models.Model):
    # to be set in the concrete models:
    # artifact_type - str - The reference name of the artifact
    # artifact_can_be_removed - boolean - If we should/can send the command to remove it or not.

    # install it during the AwaitingConfiguration phase ?
    install_before_setup_assistant = models.BooleanField(default=False)

    # devices
    # TODO: add tags
    meta_business_unit = models.ForeignKey(MetaBusinessUnit,
                                           related_name="%(app_label)s_%(class)s",
                                           editable=False,
                                           on_delete=models.CASCADE)

    # version
    version = models.PositiveIntegerField(default=0, editable=False)

    # timestamps
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    trashed_at = models.DateTimeField(null=True, editable=False)

    class Meta:
        abstract = True


# Pushed artifacts


class InstalledDeviceArtifact(models.Model):
    enrolled_device = models.ForeignKey(EnrolledDevice, on_delete=models.CASCADE)

    # artifact
    artifact_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    artifact_id = models.PositiveIntegerField()
    artifact = GenericForeignKey("artifact_content_type", "artifact_id")
    artifact_version = models.PositiveIntegerField()

    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        unique_together = ("enrolled_device", "artifact_content_type", "artifact_id")


class DeviceArtifactCommand(models.Model):
    ACTION_INSTALL = "INSTALL"
    ACTION_REMOVE = "REMOVE"
    ACTION_CHOICES = (
        (ACTION_INSTALL, "Install"),
        (ACTION_REMOVE, "Remove"),
    )

    # artifact
    artifact_content_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    artifact_id = models.PositiveIntegerField()
    artifact = GenericForeignKey("artifact_content_type", "artifact_id")
    artifact_version = models.PositiveIntegerField()

    # action
    action = models.CharField(max_length=64, choices=ACTION_CHOICES)

    # command
    command = models.OneToOneField(DeviceCommand, on_delete=models.CASCADE)


# Kernel extension policy


class KernelExtensionTeam(models.Model):
    name = models.TextField(unique=True)
    identifier = models.CharField(max_length=10, unique=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return "{} {}".format(self.name, self.identifier)

    def get_absolute_url(self):
        return "{}#team_{}".format(reverse("mdm:kernel_extensions_index"), self.identifier)


class KernelExtension(models.Model):
    team = models.ForeignKey(KernelExtensionTeam, on_delete=models.PROTECT)
    name = models.TextField(unique=True)
    identifier = models.TextField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)

    class Meta:
        ordering = ("team__name", "name")

    def __str__(self):
        return "{} - {} {}".format(self.team, self.name, self.identifier)

    def get_absolute_url(self):
        return "{}#kext_{}".format(reverse("mdm:kernel_extensions_index"), self.identifier)


class KernelExtensionPolicy(BaseArtifact):
    artifact_type = "ConfigurationProfile"
    artifact_can_be_removed = True

    # content
    allow_user_overrides = models.BooleanField(help_text=("If set to true, users can approve additional kernel "
                                                          "extensions not explicitly allowed by configuration "
                                                          "profiles"),
                                               default=True)
    allowed_teams = models.ManyToManyField(KernelExtensionTeam, blank=True)
    allowed_kernel_extensions = models.ManyToManyField(KernelExtension, blank=True)

    def get_absolute_url(self):
        return reverse("mdm:kernel_extension_policy", args=(self.meta_business_unit.pk, self.pk))

    def __str__(self):
        return "{} kernel extension policy".format(self.meta_business_unit)

    def save(self, *args, **kwargs):
        if self.pk:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    def get_configuration_profile_payload_identifier_suffix(self):
        return "kext-policy.{}".format(self.pk)

    def get_payloads(self):
        allowed_kernel_extensions_d = {}
        for kext in self.allowed_kernel_extensions.all():
            allowed_kernel_extensions_d.setdefault(kext.team.identifier, []).append(kext.identifier)
        payload = {"AllowUserOverrides": self.allow_user_overrides,
                   "AllowedTeamIdentifiers": [team.identifier for team in self.allowed_teams.all()],
                   "AllowedKernelExtensions": allowed_kernel_extensions_d}
        yield "com.apple.syspolicy.kernel-extension-policy", str(self), payload


# Enrollment packages


def enrollment_package_path(instance, filename):
    # TODO overflow ?
    return 'mdm/meta_business_unit/{0:08d}/enrollment_packages/{1}'.format(
        instance.meta_business_unit.id,
        filename
    )


class MDMEnrollmentPackage(BaseArtifact):
    artifact_type = "Application"
    artifact_can_be_removed = False  # TODO: not implemented. Verify if possible.

    # content
    builder = models.CharField(max_length=256)
    enrollment_pk = models.PositiveIntegerField()
    file = models.FileField(upload_to=enrollment_package_path, blank=True)
    manifest = JSONField(blank=True, null=True)

    def __str__(self):
        enrollment = self.get_enrollment()
        if enrollment:
            return enrollment.get_description_for_distributor()
        else:
            return "{} {}".format(self.get_description_for_enrollment(),
                                  self.builder.split(".")[-1])

    def enrollment_update_callback(self):
        self.version = F("version") + 1
        self.save()
        self.refresh_from_db()
        build_mdm_enrollment_package(self)

    def get_builder_class(self):
        return get_standalone_package_builders()[self.builder]

    def get_enrollment(self):
        try:
            enrollment_model = self.get_builder_class().form.Meta.model
            return enrollment_model.objects.get(pk=self.enrollment_pk)
        except (AttributeError, ObjectDoesNotExist):
            pass

    def delete(self, *args, **kwargs):
        self.file.delete(save=False)
        enrollment = self.get_enrollment()
        if enrollment:
            enrollment.delete()

    def get_description_for_enrollment(self):
        return "MDM enrollment package"

    def serialize_for_event(self):
        """used for the enrollment secret verification events, via the enrollment"""
        return {"mdm_enrollment_package": {"pk": self.pk,
                                           "version": self.version,
                                           "meta_business_unit": {"pk": self.meta_business_unit.pk,
                                                                  "name": str(self.meta_business_unit)}}}

    def get_enrollment_package_filename(self):
        return "{}.pkg".format(slugify("{} pk{} v{}".format(self.get_builder_class().name,
                                                            self.id,
                                                            self.version)))

    def get_absolute_url(self):
        return "{}#enrollment_package_{}".format(reverse("mdm:mbu",
                                                         args=(self.meta_business_unit.pk,)), self.pk)

    def save(self, *args, **kwargs):
        if not self.trashed_at:
            query_set = MDMEnrollmentPackage.objects.filter(meta_business_unit=self.meta_business_unit,
                                                            builder=self.builder,
                                                            trashed_at__isnull=True)
            if self.pk:
                query_set = query_set.exclude(pk=self.pk)
            if query_set.count():
                raise ValueError("An active enrollment package for this business unit "
                                 "and this builder already exists.")
        super(MDMEnrollmentPackage, self).save(*args, **kwargs)


# Configuration profiles


class ConfigurationProfile(BaseArtifact):
    artifact_type = "ConfigurationProfile"
    artifact_can_be_removed = True

    # content
    source = JSONField()
    source_payload_identifier = models.TextField(editable=False)
    payload_display_name = models.TextField(blank=True, null=True, editable=False)
    payload_description = models.TextField(blank=True, null=True, editable=False)

    def __str__(self):
        if self.payload_display_name:
            return self.payload_display_name
        else:
            return "Configuration Profile {}".format(self.pk)

    class Meta:
        unique_together = (("meta_business_unit", "source_payload_identifier"),)

    def save(self, *args, **kwargs):
        if self.pk:
            self.version = F("version") + 1
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return "{}#configuration_profile_{}".format(reverse("mdm:mbu",
                                                            args=(self.meta_business_unit.pk,)), self.pk)

    def get_configuration_profile_payload_identifier_suffix(self):
        return "configuration-profile.{}".format(self.pk)

    def get_payloads(self):
        for idx, payload in enumerate(self.source.get("PayloadContent", [])):
            payload_name = payload.get("PayloadDisplayName", "{} #{}".format(self, idx + 1))
            payload_content = {k: v for k, v in payload.items() if not k.startswith("Payload")}
            yield payload["PayloadType"], payload_name, payload_content
