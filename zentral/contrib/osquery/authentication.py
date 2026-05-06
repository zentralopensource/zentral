from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import Enrollment


class OsqueryEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    keyword = "ZtlOsqueryEnrollmentSecret"
    enrollment_model = Enrollment
