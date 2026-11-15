from pbac.engine import engine
from pbac.entities import Namespace
from zentral.contrib.inventory.pbac import register_view_enrollment_secret

from .models import Enrollment


# namespace


NAMESPACE_ID = "Munki"


def get_namespace() -> Namespace:
    return engine.get_namespace(NAMESPACE_ID)


# actions


ViewEnrollmentSecretRequest = register_view_enrollment_secret(
    get_namespace(), Enrollment, "viewEnrollmentSecret", "Enrollment",
)
view_enrollment_secret_action = ViewEnrollmentSecretRequest.pbac_action
