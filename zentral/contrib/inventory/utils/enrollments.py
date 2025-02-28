import logging
from zentral.contrib.inventory.exceptions import EnrollmentSecretVerificationFailed
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.inventory.events import (post_enrollment_secret_verification_failure,
                                              post_enrollment_secret_verification_success)


__all__ = [
    "verify_enrollment_secret",
]


logger = logging.getLogger("zentral.contrib.inventory.utils.enrollments")


def verify_enrollment_secret(model, secret,
                             user_agent, public_ip_address,
                             serial_number=None, udid=None,
                             meta_business_unit=None,
                             **kwargs):
    try:
        request = EnrollmentSecret.objects.verify(model, secret,
                                                  user_agent, public_ip_address,
                                                  serial_number, udid,
                                                  meta_business_unit,
                                                  **kwargs)
    except EnrollmentSecretVerificationFailed as e:
        post_enrollment_secret_verification_failure(model,
                                                    user_agent, public_ip_address, serial_number,
                                                    e.err_msg, e.enrollment_secret)
        raise
    else:
        post_enrollment_secret_verification_success(request, model)
        return request
