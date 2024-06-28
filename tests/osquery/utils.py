from django.utils.crypto import get_random_string
from zentral.contrib.osquery.models import Configuration, Enrollment
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit


def force_configuration():
    return Configuration.objects.create(
        name=get_random_string(12),
    )


def force_enrollment(
    configuration=None,
    enrollment_secret=None,
    meta_business_unit=None,
    tags=None,
):
    if configuration is None:
        configuration = force_configuration()
    if enrollment_secret is None:
        if meta_business_unit is None:
            meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(12))
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=meta_business_unit)
    if tags:
        enrollment_secret.tags.set(tags)
    return Enrollment.objects.create(
        configuration=configuration,
        secret=enrollment_secret
    )
