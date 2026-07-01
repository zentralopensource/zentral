import plistlib

from zentral.conf import settings
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier, sign_payload


def build_turbo_enrollment_configuration(enrollment):
    # Managed defaults for the com.zentral.turbo domain. The agent reads BaseURL as the host root and
    # appends public/turbo/ itself, then exchanges EnrollmentSecret for a per-device token at enroll time.
    return {
        "BaseURL": settings["api"]["tls_hostname"],
        "EnrollmentSecret": enrollment.secret.secret,
    }


def build_configuration_plist(enrollment):
    content = plistlib.dumps(build_turbo_enrollment_configuration(enrollment))
    return f"zentral_turbo_configuration.enrollment_{enrollment.pk}.plist", content


def build_configuration_profile(enrollment):
    identifier = get_payload_identifier("turbo_configuration")
    # modern flat custom-settings payload: the managed keys sit directly on a com.zentral.turbo payload,
    # no com.apple.ManagedClient.preferences / mcx_preference_settings nesting
    payload_content = {
        **build_turbo_enrollment_configuration(enrollment),
        "PayloadEnabled": True,
        "PayloadIdentifier": identifier,
        "PayloadUUID": generate_payload_uuid(),
        "PayloadType": "com.zentral.turbo",
        "PayloadVersion": 1
    }

    configuration_profile_data = {
        "PayloadContent": [payload_content],
        "PayloadDisplayName": "Zentral - Turbo configuration",
        "PayloadDescription": "Turbo configuration for Zentral",
        "PayloadIdentifier": identifier,
        "PayloadOrganization": "Zentral",
        "PayloadRemovalDisallowed": True,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": generate_payload_uuid(),
        "PayloadVersion": 1
    }

    content = sign_payload(plistlib.dumps(configuration_profile_data))
    return f"{identifier}.mobileconfig", content
