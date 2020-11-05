import logging
import plistlib
from django.http import HttpResponse
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.certificates import split_certificate_chain
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier
from zentral.utils.payloads import sign_payload_openssl
from .models import OTAEnrollment, OTAEnrollmentSession


logger = logging.getLogger("zentral.contrib.mdm.payloads")


def build_configuration_profile_response(data, filename):
    response = HttpResponse(data, content_type="application/x-apple-aspen-config")
    response['Content-Disposition'] = 'attachment; filename="{}.mobileconfig"'.format(filename)
    return response


def build_profile(display_name, suffix, content,
                  payload_type="Configuration", payload_description=None,
                  sign=True, encrypt=False):
    profile = {"PayloadUUID": generate_payload_uuid(),
               "PayloadIdentifier": get_payload_identifier(suffix),
               "PayloadVersion": 1,
               "PayloadDisplayName": display_name,
               "PayloadType": payload_type,  # Only known exception: "Profile Service"
               "PayloadContent": content}
    if payload_description:
        profile["PayloadDescription"] = payload_description
    data = plistlib.dumps(profile)
    if sign:
        data = sign_payload_openssl(data)
    return data


def build_payload(payload_type, payload_display_name, suffix, content, payload_version=1, encapsulate_content=False):
    payload = {"PayloadUUID": generate_payload_uuid(),
               "PayloadType": payload_type,
               "PayloadDisplayName": payload_display_name,
               "PayloadIdentifier": get_payload_identifier(suffix),
               "PayloadVersion": payload_version}
    if encapsulate_content:
        # for scep, certificates TODO: what else ?
        payload["PayloadContent"] = content
    else:
        payload.update(content)
    return payload


# TODO: BAD. Must check if this is really a root CA before building returning anything
def build_root_ca_payloads():
    root_certificate = split_certificate_chain(settings["api"]["tls_fullchain"])[-1]
    return [
        build_payload("com.apple.security.pem",
                      "Zentral - root CA", "tls-root-ca-cert",
                      root_certificate.encode("utf-8"),
                      encapsulate_content=True)
    ]


def build_root_ca_configuration_profile():
    return build_profile("Zentral - root CA certificates",
                         "root-ca-certificates",
                         build_root_ca_payloads())


def build_scep_payload(enrollment_session):
    return build_payload("com.apple.security.scep",
                         enrollment_session.get_payload_name(),
                         "scep",
                         {"URL": "{}/scep".format(settings["api"]["tls_hostname"]),  # TODO: hardcoded scep url
                          "Subject": [[["CN", enrollment_session.get_common_name()]],
                                      [["2.5.4.5", enrollment_session.get_serial_number()]],
                                      [["O", enrollment_session.get_organization()]]],
                          "Challenge": enrollment_session.get_challenge(),
                          "Keysize": 2048,
                          "KeyType": "RSA",
                          "Key Usage": 5,  # 1 is signing, 4 is encryption, 5 is both signing and encryption
                          },
                         encapsulate_content=True)


def build_profile_service_configuration_profile(ota_obj):
    if isinstance(ota_obj, OTAEnrollmentSession):
        url_path = reverse("mdm:ota_session_enroll")
    elif isinstance(ota_obj, OTAEnrollment):
        url_path = reverse("mdm:ota_enroll")
    else:
        raise ValueError("ota_obj not an OTAEnrollment nor an OTAEnrollmentSession")
    return build_profile("Zentral - OTA MDM Enrollment",
                         "profile-service",
                         {"URL": "{}{}".format(settings["api"]["tls_hostname"], url_path),
                          "DeviceAttributes": ["UDID",
                                               "VERSION",
                                               "PRODUCT",
                                               "SERIAL",
                                               "MEID",
                                               "IMEI"],
                          "Challenge": ota_obj.enrollment_secret.secret},
                         payload_type="Profile Service",
                         payload_description="Install this profile to enroll your device with Zentral")


def build_ota_scep_configuration_profile(ota_enrollment_session):
    return build_profile(ota_enrollment_session.get_payload_name(), "scep",
                         [build_scep_payload(ota_enrollment_session)])


def build_mdm_configuration_profile(enrollment_session, push_certificate):
    scep_payload = build_scep_payload(enrollment_session)
    payloads = build_root_ca_payloads()
    payloads.extend([
        scep_payload,
        build_payload("com.apple.mdm",
                      "Zentral - MDM",
                      "mdm",
                      {"IdentityCertificateUUID": scep_payload["PayloadUUID"],
                       "Topic": push_certificate.topic,
                       "ServerURL": "{}{}".format(
                           settings["api"]["tls_hostname_for_client_cert_auth"],
                           reverse("mdm:connect")),
                       "ServerCapabilities": ["com.apple.mdm.per-user-connections"],
                       "CheckInURL": "{}{}".format(
                           settings["api"]["tls_hostname_for_client_cert_auth"],
                           reverse("mdm:checkin")),
                       "CheckOutWhenRemoved": True,
                       "AccessRights": 8191,  # TODO: config
                       })
    ])
    return build_profile("Zentral - MDM enrollment", "mdm", payloads)
