import base64
from datetime import timedelta
import logging
from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from zentral.contrib.inventory.models import EnrollmentSecret, EnrollmentSecretRequest, MetaBusinessUnit
from .exceptions import EnrollmentSessionStatusError

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


class EnrolledDevice(models.Model):
    push_certificate = models.ForeignKey(PushCertificate, on_delete=models.CASCADE)
    serial_number = models.TextField(db_index=True)
    udid = models.CharField(max_length=36, unique=True)
    token = models.BinaryField(blank=True, null=True)
    push_magic = models.TextField(blank=True, null=True)
    unlock_token = models.BinaryField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class EnrolledUser(models.Model):
    enrolled_device = models.ForeignKey(EnrolledDevice)
    user_id = models.CharField(max_length=36, unique=True)
    long_name = models.TextField()
    short_name = models.TextField()
    token = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# Common mixin for OTA and DEP enrollments
# Manage the SCEP certificates and some state


class EnrollmentSessionMixin(object):
    def get_common_name(self):
        return "{prefix}${secret}".format(prefix=self.get_prefix(),
                                          secret=self.enrollment_secret.secret)

    def get_organization(self):
        return "MBU${}".format(self.enrollment_secret.meta_business_unit.pk)

    def get_serial_number(self):
        return self.enrollment_secret.serial_numbers[0]

    def get_challenge(self):
        path = reverse("mdm:verify_scep_csr")
        return base64.b64encode(path.encode("utf-8")).decode("ascii")

    def get_payload_name(self):
        return "Zentral - {prefix} Enrollment SCEP".format(prefix=" - ".join(self.get_prefix().split("$")))

    def is_completed(self):
        return self.status == self.COMPLETED

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
    enrollment_secret = models.OneToOneField(EnrollmentSecret, related_name="ota_enrollment")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "name": self.name,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"ota_enrollment": d}

    def get_absolute_url(self):
        return reverse("mdm:ota_enrollment", args=(self.pk,))

    def revoke(self):
        if not self.enrollment_secret.revoked_at:
            # TODO events
            self.enrollment_secret.revoked_at = timezone.now()
            self.enrollment_secret.save()
            self.save()


class OTAEnrollmentSessionManager(models.Manager):
    def create_from_ota_enrollment(self, ota_enrollment, serial_number, udid):
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
        new_es.tags = tags
        return self.create(status=self.model.PHASE_2,
                           ota_enrollment=ota_enrollment,
                           enrollment_secret=new_es)


class OTAEnrollmentSession(models.Model, EnrollmentSessionMixin):
    PHASE_2 = "PHASE_2"
    PHASE_2_SCEP_VERIFIED = "PHASE_2_SCEP_VERIFIED"
    PHASE_3 = "PHASE_3"
    PHASE_3_SCEP_VERIFIED = "PHASE_3_SCEP_VERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (PHASE_2, _("Phase 2")),
        (PHASE_2_SCEP_VERIFIED, _("Phase 2 SCEP verified")),
        (PHASE_3, _("Phase 3")),
        (PHASE_3_SCEP_VERIFIED, _("Phase 3 SCEP verified")),
        (AUTHENTICATED, _("Authenticated")),  # first MDM Checkin Authenticate call
        (COMPLETED, _("Completed")),  # first MDM Checkin TokenUpdate call
    )
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    ota_enrollment = models.ForeignKey(OTAEnrollment, on_delete=models.CASCADE)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, related_name="ota_enrollment_session")
    phase2_scep_request = models.ForeignKey(EnrollmentSecretRequest, null=True, related_name="+")
    phase3_scep_request = models.ForeignKey(EnrollmentSecretRequest, null=True, related_name="+")
    enrolled_device = models.ForeignKey(EnrolledDevice, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = OTAEnrollmentSessionManager()

    def get_prefix(self):
        if self.status == self.PHASE_2:
            return "OTA"
        elif self.status == self.PHASE_3:
            return "MDM$OTA"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "status": self.status,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"ota_enrollment": self.ota_enrollment.serialize_for_event(),
                "ota_enrollment_session": d}

    # status update methods

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
        return "{} - DEP token".format(self.meta_business_unit.name)

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

    organization = models.ForeignKey(DEPOrganization, editable=False)
    token = models.OneToOneField(DEPToken, editable=False, null=True, related_name="virtual_server")

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
        ("HomeButtonSensitivity", True),
        ("OnBoarding", True),
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
    virtual_server = models.ForeignKey(DEPVirtualServer, on_delete=models.CASCADE, editable=False)
    uuid = models.UUIDField(unique=True, editable=False)

    # standard DEP profile configuration
    name = models.CharField(max_length=125, unique=True)  # see CONFIG_NAME_INVALID error
    allow_pairing = models.BooleanField(default=False)
    is_supervised = models.BooleanField(default=True)
    is_multi_user = models.BooleanField(default=True)
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
    enrollment_secret = models.OneToOneField(EnrollmentSecret, related_name="dep_profile", editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("mdm:dep_profile", args=(self.pk,))

    def get_meta_business_unit(self):
        return self.enrollment_secret.meta_business_unit

    def serialize_for_event(self):
        return {"pk": self.pk,
                "uuid": self.uuid,
                "name": self.name,
                "created_at": self.created_at,
                "updated_at": self.updated_at}


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
    profile_status = models.CharField(max_length=64, choices=PROFILE_STATUS_CHOICES, editable=False)
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
        return "{}#{}".format(reverse("mdm:dep_virtual_server", args=(self.virtual_server.pk,)),
                              self.serial_number)


class DEPEnrollmentSessionManager(models.Manager):
    def create_from_dep_profile(self, dep_profile, serial_number, udid):
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
        new_es.tags = tags
        return self.create(status=self.model.STARTED,
                           dep_profile=dep_profile,
                           enrollment_secret=new_es)


class DEPEnrollmentSession(models.Model, EnrollmentSessionMixin):
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
    dep_profile = models.ForeignKey(DEPProfile, on_delete=models.CASCADE)
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, related_name="dep_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, null=True, related_name="+")
    enrolled_device = models.ForeignKey(EnrolledDevice, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = DEPEnrollmentSessionManager()

    def get_prefix(self):
        if self.status == self.STARTED:
            return "MDM$DEP"
        else:
            raise ValueError("Wrong enrollment sessions status")

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "status": self.status,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"dep_profile": self.dep_profile.serialize_for_event(),
                "dep_enrollment_session": d}

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
