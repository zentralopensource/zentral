import plistlib
from zentral.conf import settings
from zentral.utils.osx_package import distribute_tls_server_certs, TLS_SERVER_CERTS_CLIENT_PATH
from zentral.utils.payloads import generate_payload_uuid, get_payload_identifier, sign_payload_openssl


def build_santa_configuration_dict(enrolled_machine):
    configuration = enrolled_machine.enrollment.configuration

    # default attributes
    config_dict = {"MachineIDKey": "MachineID",
                   "MachineIDPlist": "/usr/local/zentral/santa/machine_id.plist",
                   "SyncBaseURL": "{}/santa/".format(settings["api"]["tls_hostname"])}
    if distribute_tls_server_certs():
        config_dict["ServerAuthRootsFile"] = TLS_SERVER_CERTS_CLIENT_PATH

    # configuration attributes
    config_dict.update(configuration.get_local_config())

    return config_dict


def build_config_plist(enrolled_machine):
    content = plistlib.dumps(build_santa_configuration_dict(enrolled_machine))
    return "config.plist", content.decode("utf-8")


def build_configuration_profile(enrolled_machine):
    configuration = enrolled_machine.enrollment.configuration

    payload_content = {"PayloadContent": {"com.google.santa": {"Forced": [
                            {"mcx_preference_settings": build_santa_configuration_dict(enrolled_machine)}
                        ]}},
                       "PayloadEnabled": True,
                       "PayloadIdentifier": get_payload_identifier("santa.configuration.{}".format(configuration.pk)),
                       "PayloadUUID": generate_payload_uuid(),
                       'PayloadType': 'com.apple.ManagedClient.preferences',
                       'PayloadVersion': 1}

    configuration_profile_data = {"PayloadContent": [payload_content],
                                  "PayloadDisplayName": "Zentral - Santa settings",
                                  "PayloadDescription": "Google Santa settings for Zentral",
                                  "PayloadIdentifier": "com.google.santa",
                                  "PayloadOrganization": "Zentral",
                                  "PayloadRemovalDisallowed": True,
                                  "PayloadScope": "System",
                                  "PayloadType": "Configuration",
                                  "PayloadUUID": generate_payload_uuid(),
                                  "PayloadVersion": 1}

    content = sign_payload_openssl(plistlib.dumps(configuration_profile_data))
    return "com.google.santa.zentral.mobileconfig", content
