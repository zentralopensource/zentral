import logging
import plistlib
from urllib.parse import urlparse
import uuid
from django.http import HttpResponse
from django.urls import reverse
from zentral.conf import settings
from zentral.utils.certificates import split_certificate_chain


logger = logging.getLogger("zentral.contrib.mdm.payloads")


def build_payload_response(payload, filename):
    response = HttpResponse(payload, content_type="application/x-apple-aspen-config")
    response['Content-Disposition'] = 'attachment; filename="{}.mobileconfig"'.format(filename)
    return response


def get_payload_identifier(suffix):
    o = urlparse(settings["api"]["tls_hostname"])
    netloc = o.netloc.split(":")[0].split(".")
    netloc.reverse()
    netloc.append(suffix)
    return ".".join(netloc)


def build_payload(display_name, suffix, content,
                  payload_type="Configuration", payload_description=None, merge_content=False):
    payload = {"PayloadUUID": str(uuid.uuid4()),
               "PayloadIdentifier": get_payload_identifier(suffix),
               "PayloadVersion": 1,
               "PayloadDisplayName": display_name,
               "PayloadType": payload_type}
    if payload_description:
        payload["PayloadDescription"] = payload_description
    if merge_content:
        payload.update(content)
    else:
        payload["PayloadContent"] = content
    return payload


def build_root_ca_payloads():
    root_certificates = []
    payloads = []
    for api_settings_attr, name, suffix in (("tls_server_certs",
                                             "Zentral - root CA",
                                             "tls-root-ca-cert"),
                                            ("tls_server_certs_client_certificate_authenticated",
                                             "Zentral client certificate authenticated - root CA",
                                             "tls-clicertauth-root-ca")):
        if api_settings_attr not in settings["api"]:
            logger.warning("Missing %s key in api settings", api_settings_attr)
            continue
        certificate_chain_filename = settings["api"][api_settings_attr]
        root_certificate = split_certificate_chain(certificate_chain_filename)[-1]
        if root_certificate not in root_certificates:
            payloads.append(build_payload(name, suffix,
                                          root_certificate.encode("utf-8"),
                                          "com.apple.security.pem"))
    return payloads


def build_root_ca_configuration_profile():
    return plistlib.dumps(build_payload("Zentral - root CA certificate",
                                        "root-ca-certificate",
                                        build_root_ca_payloads()))


def build_scep_payload(enrollment_session):
    return build_payload(enrollment_session.get_payload_name(),
                         "scep",
                         {"URL": "{}/scep".format(settings["api"]["tls_hostname"]),
                          "Subject": [[["CN", enrollment_session.get_common_name()]],
                                      [["2.5.4.5", enrollment_session.get_serial_number()]],
                                      [["O", enrollment_session.get_organization()]]],
                          "Challenge": enrollment_session.get_challenge(),
                          "Keysize": 2048,
                          "KeyType": "RSA",
                          "KeyUsage": 5,  # 1 is signing, 4 is encryption, 5 is both signing and encryption
                          },
                         "com.apple.security.scep")


def build_profile_service_payload(ota_enrollment):
    return plistlib.dumps(build_payload("Zentral - OTA MDM Enrollment",
                                        "profile-service",
                                        {"URL": "{}{}".format(settings["api"]["tls_hostname"],
                                                              reverse("mdm:ota_enroll")),
                                         "DeviceAttributes": ["UDID",
                                                              "VERSION",
                                                              "PRODUCT",
                                                              "SERIAL",
                                                              "MEID",
                                                              "IMEI"],
                                         "Challenge": ota_enrollment.enrollment_secret.secret
                                         },
                                        "Profile Service",
                                        "Install this profile to enroll your device with Zentral",
                                        ))


def build_ota_scep_payload(ota_enrollment_session):
    content = [build_scep_payload(ota_enrollment_session)]
    return plistlib.dumps(build_payload(ota_enrollment_session.get_payload_name(), "scep", content))


def build_mdm_payload(enrollment_session, push_certificate):
    scep_payload = build_scep_payload(enrollment_session)
    content = build_root_ca_payloads()
    content.extend([
        scep_payload,
        build_payload("Zentral - MDM",
                      "mdm",
                      {"IdentityCertificateUUID": scep_payload["PayloadUUID"],
                       "Topic": push_certificate.topic,
                       "ServerURL": "{}{}".format(
                           settings["api"]["tls_hostname_client_certificate_authenticated"],
                           reverse("mdm:connect")),
                       "ServerCapabilities": ["com.apple.mdm.per-user-connections"],
                       "CheckInURL": "{}{}".format(
                           settings["api"]["tls_hostname_client_certificate_authenticated"],
                           reverse("mdm:checkin")),
                       "CheckOutWhenRemoved": True,
                       "AccessRights": 8191,  # TODO: config
                       },
                      "com.apple.mdm",
                      merge_content=True)
    ])
    return plistlib.dumps(build_payload("Zentral - MDM enrollment", "mdm", content))
