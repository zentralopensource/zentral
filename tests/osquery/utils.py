from django.utils.crypto import get_random_string
from zentral.contrib.osquery.models import Configuration, Enrollment
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.core.events.base import AuditEvent


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


def assert_audit_event(test_case, post_event, action, instance, prev_value=None, call_index=0):
    """Check the audit event at call_index, and give its payload back for further assertions."""
    test_case.maxDiff = None
    event = post_event.call_args_list[call_index].args[0]
    test_case.assertIsInstance(event, AuditEvent)
    expected = {"action": action,
                "object": {"model": instance._meta.label_lower,
                           "pk": str(instance.pk)}}
    if action in ("created", "updated"):
        expected["object"]["new_value"] = instance.serialize_for_event()
    if prev_value is not None:
        expected["object"]["prev_value"] = prev_value
    test_case.assertEqual(event.payload, expected)
    metadata = event.metadata.serialize()
    test_case.assertEqual(sorted(metadata["tags"]), ["osquery", "zentral"])
    return event.payload, metadata
