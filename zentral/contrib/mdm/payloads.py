import logging
import plistlib
from django.http import HttpResponse
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.certificates import split_certificate_chain
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier
from zentral.utils.payloads import sign_payload
from .crypto import verify_signed_payload
from .models import Channel, OTAEnrollment, OTAEnrollmentSession
from .scep import update_scep_payload


logger = logging.getLogger("zentral.contrib.mdm.payloads")


def get_configuration_profile_info(data):
    info = {}
    try:
        _, data = verify_signed_payload(data)
    except Exception:
        # probably not a signed payload
        pass
    try:
        payload = plistlib.loads(data)
    except Exception:
        raise ValueError("Not a plist")
    # payload identifier
    try:
        info["payload_identifier"] = payload["PayloadIdentifier"]
    except KeyError:
        raise ValueError("Missing PayloadIdentifier")
    # payload uuid
    try:
        info["payload_uuid"] = payload["PayloadUUID"]
    except KeyError:
        raise ValueError("Missing PayloadUUID")
    # channel
    payload_scope = payload.get("PayloadScope", "User")
    if payload_scope == "System":
        info["channel"] = Channel.DEVICE
    elif payload_scope == "User":
        info["channel"] = Channel.USER
    else:
        raise ValueError(f"Unknown PayloadScope: {payload_scope}")
    # other keys
    for payload_key, info_key in (("PayloadDisplayName", "payload_display_name"),
                                  ("PayloadDescription", "payload_description")):
        info[info_key] = payload.get(payload_key) or ""
    return data, info


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
        data = sign_payload(data)
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
    subject = [[["CN", enrollment_session.get_common_name()]]]
    serial_number = enrollment_session.get_serial_number()
    if serial_number:
        subject.append([["2.5.4.5", serial_number]])
    subject.append([["O", enrollment_session.get_organization()]])
    scep_payload = {"Subject": subject}
    update_scep_payload(scep_payload, enrollment_session.get_enrollment().scep_config)
    return build_payload("com.apple.security.scep",
                         enrollment_session.get_payload_name(),
                         "scep",
                         scep_payload,
                         encapsulate_content=True)


def build_profile_service_configuration_profile(ota_obj):
    if isinstance(ota_obj, OTAEnrollmentSession):
        url_path = reverse("mdm_public:ota_session_enroll")
    elif isinstance(ota_obj, OTAEnrollment):
        url_path = reverse("mdm_public:ota_enroll")
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


def build_mdm_configuration_profile(enrollment_session):
    scep_payload = build_scep_payload(enrollment_session)
    payloads = build_root_ca_payloads()
    mdm_config = {
        "IdentityCertificateUUID": scep_payload["PayloadUUID"],
        "Topic": enrollment_session.get_enrollment().push_certificate.topic,
        "ServerCapabilities": ["com.apple.mdm.bootstraptoken",
                               "com.apple.mdm.per-user-connections"],
        "CheckOutWhenRemoved": True,
    }
    if settings["apps"]["zentral.contrib.mdm"].get("mtls_proxy", True):
        fqdn_key = "fqdn_mtls"
    else:
        mdm_config["SignMessage"] = True
        fqdn_key = "fqdn"
    mdm_config["ServerURL"] = "https://{}{}".format(settings["api"][fqdn_key], reverse("mdm_public:connect"))
    mdm_config["CheckInURL"] = "https://{}{}".format(settings["api"][fqdn_key], reverse("mdm_public:checkin"))
    managed_apple_id = getattr(enrollment_session, "managed_apple_id", None)
    if managed_apple_id:
        if enrollment_session.access_token:
            # account-driven user enrollment
            mdm_config["AssignedManagedAppleID"] = managed_apple_id
            mdm_config["EnrollmentMode"] = "BYOD"
        else:
            # unauthenticated user enrollment
            mdm_config["ManagedAppleID"] = managed_apple_id
    else:
        mdm_config["AccessRights"] = 8191  # TODO: config
    payloads.extend([
        scep_payload,
        build_payload("com.apple.mdm",
                      "Zentral - MDM",
                      "mdm", mdm_config)
    ])
    return build_profile("Zentral - MDM enrollment", "mdm", payloads)


def substitute_variables(obj, enrollment_session, enrolled_user=None):
    if isinstance(obj, dict):
        obj = {k: substitute_variables(v, enrollment_session, enrolled_user) for k, v in obj.items()}
    elif isinstance(obj, list):
        obj = [substitute_variables(i, enrollment_session, enrolled_user) for i in obj]
    elif isinstance(obj, str):
        enrolled_device = enrollment_session.enrolled_device
        for attr in ("serial_number", "udid"):
            obj = obj.replace(f"$ENROLLED_DEVICE.{attr.upper()}",
                              getattr(enrolled_device, attr))
        if enrolled_user:
            for attr in ("long_name", "short_name"):
                obj = obj.replace(f"$ENROLLED_USER.{attr.upper()}",
                                  getattr(enrolled_user, attr))
        realm_user = enrollment_session.realm_user
        if realm_user:
            for attr in ("username", "device_username",
                         "email_prefix", "email_prefix",  # WARNING order is important
                         "email", "email",
                         "first_name", "last_name", "full_name"):
                obj = obj.replace(f"$REALM_USER.{attr.upper()}",
                                  getattr(realm_user, attr))
        managed_apple_id = getattr(enrollment_session, "managed_apple_id", None)
        if managed_apple_id:
            obj = obj.replace("$MANAGED_APPLE_ID.EMAIL", managed_apple_id)
    return obj
