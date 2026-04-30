from zentral.contrib.inventory.authentication import EnrollmentSecretAuthentication

from .models import Enrollment


class MunkiEnrollmentSecretAuthentication(EnrollmentSecretAuthentication):
    enrollment_model = Enrollment
    enrollment_token = "munki_enrollment"
    enrollment_select_related = ()
