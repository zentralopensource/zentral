#!/usr/bin/python
import json
import os
import plistlib
import ssl
import subprocess
import urllib2

MIN_CONFIGURATION_PROFILE_SANTA_VERSION = (0, 9, 21)

USER_AGENT = "Zentral/santaenrollment 0.1"

ENROLLMENT_URL = """%ENROLLMENT_URL%"""

ENROLLMENT_SECRET = """%ENROLLMENT_SECRET%"""

ZENTRAL_DIR = "/usr/local/zentral/"

ZENTRAL_SANTA_DIR = os.path.join(ZENTRAL_DIR, "santa")


def version_tuple_from_version_str(version):
    return tuple(int(i) for i in version.split("."))


def get_santa_versions():
    try:
        version_dict = json.loads(subprocess.check_output(["santactl", "version", "--json"]))
        return set(version_tuple_from_version_str(version.split()[0]) for version in version_dict.values())
    except OSError:
        return set([])


def get_max_santa_version():
    try:
        return max(get_santa_versions())
    except ValueError:
        return None


def get_serial_number_and_uuid():
    output = subprocess.check_output(["ioreg", "-a", "-c", "IOPlatformExpertDevice", "-d", "2"])
    ioreg_result = plistlib.readPlistFromString(output)["IORegistryEntryChildren"][0]
    return ioreg_result["IOPlatformSerialNumber"], ioreg_result["IOPlatformUUID"]


def install_configuration_profile(path):
    return subprocess.check_call(["/usr/bin/profiles", "-I", "-F", path])


def post_enrollment_secret():
    req = urllib2.Request(ENROLLMENT_URL)
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Content-Type", "application/json")
    # TODO hardcoded
    ctx = ssl.create_default_context(cafile=os.path.join(ZENTRAL_DIR, "tls_server_certs.crt"))
    serial_number, uuid = get_serial_number_and_uuid()
    data = json.dumps({"secret": ENROLLMENT_SECRET,
                       "serial_number": serial_number,
                       "uuid": uuid})
    resp = urllib2.urlopen(req, data=data, context=ctx)
    return json.load(resp)


if __name__ == "__main__":
    resp = post_enrollment_secret()

    # save configuration profile content
    configuration_profile_path = os.path.join(ZENTRAL_SANTA_DIR, resp["configuration_profile"]["name"])
    with open(configuration_profile_path, "w") as f:
        f.write(resp["configuration_profile"]["content"])

    # install configuration profile
    install_configuration_profile(configuration_profile_path)

    if get_max_santa_version() < MIN_CONFIGURATION_PROFILE_SANTA_VERSION:
        # save config.plist
        with open(os.path.join(ZENTRAL_SANTA_DIR,
                               resp["config_plist"]["name"]), "w") as f:
            f.write(resp["config_plist"]["content"])
