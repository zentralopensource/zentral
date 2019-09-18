import base64
import logging
from django.contrib.postgres.fields import JSONField
from django.db import models
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from zentral.contrib.inventory.models import BaseEnrollment, EnrollmentSecret, EnrollmentSecretRequest

logger = logging.getLogger("zentral.contrib.filebeat.models")


# Configuration / Enrollment


class Configuration(models.Model):
    name = models.CharField(max_length=256, unique=True)
    inputs = JSONField(editable=False)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("filebeat:configuration", args=(self.pk,))

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        for enrollment in self.enrollment_set.all():
            # per default, will bump the enrollment version
            # and notify their distributors
            enrollment.save()


class Enrollment(BaseEnrollment):
    configuration = models.ForeignKey(Configuration, on_delete=models.CASCADE)
    filebeat_release = models.CharField(max_length=64, blank=True, null=True)

    def get_description_for_distributor(self):
        return "Filebeat configuration: {}".format(self.configuration)

    def serialize_for_event(self):
        enrollment_dict = super().serialize_for_event()
        enrollment_dict["configuration"] = {"pk": self.configuration.pk,
                                            "name": self.configuration.name}
        return enrollment_dict

    def get_absolute_url(self):
        return "{}#enrollment_{}".format(reverse("filebeat:configuration", args=(self.configuration.pk,)), self.pk)


class EnrolledMachine(models.Model):
    serial_number = models.TextField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)


class EnrollmentSessionManager(models.Manager):
    def create_from_enrollment(self, enrollment, serial_number):
        enrollment_secret = enrollment.secret
        tags = list(enrollment_secret.tags.all())
        new_es = EnrollmentSecret(
            meta_business_unit=enrollment_secret.meta_business_unit,
            serial_numbers=[serial_number],
            quota=2,  # Verified max twice. SCEP? + Enrollment completion
            expired_at=enrollment_secret.expired_at
        )
        new_es.save(secret_length=59)  # CN max 64 - $ separator - FLBT prefix
        new_es.tags.set(tags)
        return self.create(enrollment=enrollment,
                           status=self.model.STARTED,
                           enrollment_secret=new_es)


class EnrollmentSession(models.Model):
    STARTED = "STARTED"
    SCEP_VERIFIED = "SCEP_VERIFIED"
    COMPLETED = "COMPLETED"
    STATUS_CHOICES = (
        (STARTED, _("Started")),
        (SCEP_VERIFIED, _("SCEP verified")),
        (COMPLETED, _("Completed")),
    )
    enrollment = models.ForeignKey(Enrollment, on_delete=models.CASCADE)
    status = models.CharField(max_length=64, choices=STATUS_CHOICES)
    enrollment_secret = models.OneToOneField(EnrollmentSecret, on_delete=models.PROTECT,
                                             related_name="filebeat_enrollment_session")
    scep_request = models.ForeignKey(EnrollmentSecretRequest, on_delete=models.PROTECT, null=True, related_name="+")
    enrolled_machine = models.ForeignKey(EnrolledMachine, on_delete=models.CASCADE, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = EnrollmentSessionManager()

    def serialize_for_event(self):
        return {
            "pk": self.pk,
            "status": self.status,
            "enrollment": {
                "pk": self.enrollment.pk,
                "filebeat_release": self.enrollment.filebeat_release,
                "configuration": {
                    "pk": self.enrollment.configuration.pk,
                    "name": self.enrollment.configuration.name
                }
            },
            "enrollment_secret": self.enrollment_secret.serialize_for_event(),
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }

    def get_common_name(self):
        return "{}${}".format("FLBT", self.enrollment_secret.secret)

    def get_organization(self):
        return "MBU${}".format(self.enrollment_secret.meta_business_unit.pk)

    def get_challenge(self):
        path = reverse("filebeat:verify_scep_csr")
        return base64.b64encode(path.encode("utf-8")).decode("ascii")

    def set_scep_verified_status(self, scep_request):
        assert(self.status == self.STARTED and self.scep_request is None)
        self.status = self.SCEP_VERIFIED
        self.scep_request = scep_request
        self.save()

    def set_completed(self, enrolled_machine):
        assert((self.status == self.STARTED and self.scep_request is None)
               or (self.status == self.SCEP_VERIFIED and self.scep_request is not None))
        self.status = self.COMPLETED
        self.enrolled_machine = enrolled_machine
        self.save()
