from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import Enrollment


class MunkiEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    keyword = "ZtlMunkiEnrollmentSecret"
    enrollment_model = Enrollment
