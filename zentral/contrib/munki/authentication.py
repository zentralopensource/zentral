from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import Enrollment


class MunkiEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    enrollment_model = Enrollment
