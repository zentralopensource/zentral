import plistlib
from dateutil import parser
from zentral.conf import settings
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier, sign_payload_openssl


def build_santa_enrollment_configuration(enrollment):
    configuration = enrollment.configuration
    config = configuration.get_local_config()
    base_url_key = "tls_hostname"
    if configuration.client_certificate_auth:
        base_url_key = "tls_hostname_for_client_cert_auth"
    config["SyncBaseURL"] = "{}/santa/sync/{}/".format(settings["api"][base_url_key],
                                                       enrollment.secret.secret)
    return config


def build_configuration_plist(enrollment):
    content = plistlib.dumps(build_santa_enrollment_configuration(enrollment))
    return "zentral_santa_configuration.enrollment_{}.plist".format(enrollment.pk), content


def build_configuration_profile(enrollment):
    identifier = get_payload_identifier("santa_configuration")
    payload_content = {
        "PayloadContent": {"com.google.santa": {"Forced": [
            {"mcx_preference_settings": build_santa_enrollment_configuration(enrollment)}
        ]}},
        "PayloadEnabled": True,
        "PayloadIdentifier": identifier,
        "PayloadUUID": generate_payload_uuid(),
        'PayloadType': 'com.apple.ManagedClient.preferences',
        'PayloadVersion': 1
    }

    configuration_profile_data = {
        "PayloadContent": [payload_content],
        "PayloadDisplayName": "Zentral - Santa configuration",
        "PayloadDescription": "Google Santa configuration for Zentral",
        "PayloadIdentifier": identifier,
        "PayloadOrganization": "Zentral",
        "PayloadRemovalDisallowed": True,
        "PayloadScope": "System",
        "PayloadType": "Configuration",
        "PayloadUUID": generate_payload_uuid(),
        "PayloadVersion": 1
    }

    content = sign_payload_openssl(plistlib.dumps(configuration_profile_data))
    return "{}.mobileconfig".format(identifier), content


def parse_santa_log_message(message):
    d = {}
    current_attr = ""
    current_val = ""
    state = None
    for c in message:
        if state is None:
            if c == "[":
                current_attr = "timestamp"
                state = "VAL"
            elif c == ":":
                state = "ATTR"
                current_attr = ""
        elif state == "ATTR":
            if c == "=":
                state = "VAL"
            elif current_attr or c != " ":
                current_attr += c
        elif state == "VAL":
            if c == "|" or (current_attr == "timestamp" and c == "]"):
                if c == "|":
                    state = "ATTR"
                elif c == "]":
                    state = None
                if current_attr == "timestamp":
                    current_val = parser.parse(current_val)
                d[current_attr] = current_val
                current_attr = ""
                current_val = ""
            else:
                current_val += c
    if current_attr and current_val:
        d[current_attr] = current_val
    for attr, val in d.items():
        if attr.endswith("id"):
            try:
                d[attr] = int(val)
            except ValueError:
                pass
    args = d.get("args")
    if args:
        d["args"] = args.split()
    return d
