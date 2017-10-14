import base64
import logging
from django.db import models
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from zentral.contrib.inventory.models import EnrollmentSecret, EnrollmentSecretRequest, MetaBusinessUnit
from .exceptions import OTAEnrollmentSessionStatusError

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
        # Built a new secret that can be used only by one specific machine
        enrollment_secret = ota_enrollment.enrollment_secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            serial_numbers=[serial_number],
            udids=[udid],
            quota=2,  # Verified twice with 2 different SCEP payloads
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=60)  # CN max 64 - $ separator - prefix, ota or mdm
        new_es.tags = tags
        return self.create(status=self.model.PHASE_2,
                           ota_enrollment=ota_enrollment,
                           enrollment_secret=new_es)


class OTAEnrollmentSession(models.Model):
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
            return "MDM"
        else:
            raise ValueError("Wrong enrollment sessions status")

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
        return "Zentral - {prefix} Enrollment SCEP".format(prefix=self.get_prefix())

    def serialize_for_event(self):
        d = {"pk": self.pk,
             "status": self.status,
             "created_at": self.created_at,
             "updated_at": self.updated_at}
        d.update(self.enrollment_secret.serialize_for_event())
        return {"ota_enrollment": self.ota_enrollment.serialize_for_event(),
                "ota_enrollment_session": d}

    # status update methods

    def _set_next_status(self, next_status, test, **update_dict):
        if test:
            self.status = next_status
            for attr, val in update_dict.items():
                setattr(self, attr, val)
            self.save()
        else:
            raise OTAEnrollmentSessionStatusError(self, next_status)

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
