from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import Enrollment


class OsqueryEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    enrollment_model = Enrollment
