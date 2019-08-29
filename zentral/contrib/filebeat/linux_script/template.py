#!/usr/bin/python3
import configparser
import json
import os
import shutil
import ssl
import stat
import subprocess
import tempfile
import urllib.error
import urllib.request
import zipfile


START_ENROLLMENT_URL = "https://%TLS_HOSTNAME%/filebeat/enrollment/start/"
COMPLETE_ENROLLMENT_URL = "https://%TLS_HOSTNAME_FOR_CLIENT_CERT_AUTH%/filebeat/enrollment/complete/"
ENROLLMENT_SECRET = "%ENROLLMENT_SECRET%"
TLS_SERVER_CERTS = """%TLS_SERVER_CERTS%"""
DEFAULT_HEADERS = {
    "User-Agent": "Zentral-filebeatenrollment/0.1 ({lsb_description})",
    "Content-Type": "application/json"
}

ZENTRAL_DIR = "/etc/zentral/"
FILEBEAT_HOME = "/etc/filebeat"
FILEBEAT_YML = os.path.join(FILEBEAT_HOME, "filebeat.yml")
OPENSSL = "/usr/bin/openssl"
SCEPCLIENT = "/usr/local/bin/scepclient"
FILEBEAT_VERSION = "%FILEBEAT_VERSION%"
DPKG = "/usr/bin/dpkg"


def get_lsb_description():
    cp = subprocess.run([
        "lsb_release", "-a"
    ], check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
    for line in cp.stdout.decode("utf-8").splitlines():
        if line.startswith("Description:"):
            return line.split(":", 1)[-1].strip()


def prepare_default_headers():
    DEFAULT_HEADERS["User-Agent"] = DEFAULT_HEADERS["User-Agent"].format(
        lsb_description=get_lsb_description() or "Linux"
    )


def get_and_create_zentral_dir():
    os.makedirs(ZENTRAL_DIR, exist_ok=True)
    return ZENTRAL_DIR


def get_and_create_certificate_authority():
    if TLS_SERVER_CERTS:
        certificate_authority = os.path.join(get_and_create_zentral_dir(), "tls_server_certs.crt")
        with open(certificate_authority, "w") as caf:
            caf.write(TLS_SERVER_CERTS)
        return certificate_authority


def install_filebeat():
    if not FILEBEAT_VERSION:
        return
    fh, fn = tempfile.mkstemp(suffix=".deb")
    of = os.fdopen(fh, "wb")
    with urllib.request.urlopen("https://artifacts.elastic.co/downloads/beats/filebeat/"
                                "filebeat-{}-amd64.deb".format(FILEBEAT_VERSION)) as resp:
        while True:
            chunk = resp.read(64 * 2**10)
            if not chunk:
                break
            of.write(chunk)
    of.close()
    subprocess.run([
        "/usr/bin/dpkg", "-i", fn
    ], check=True)
    os.unlink(fn)


def install_scepclient():
    url = "https://github.com/micromdm/scep/releases/download/v1.0.0/scep.zip"
    # follow redirects
    while True:
        resp = urllib.request.urlopen(url)
        if resp.geturl() == url:
            break
        url = resp.geturl()
    # save zip
    tfh, tfn = tempfile.mkstemp(suffix=".zip")
    tf = os.fdopen(tfh, "wb")
    while True:
        chunk = resp.read(64 * 2**10)
        if not chunk:
            break
        tf.write(chunk)
    tf.close()
    with zipfile.ZipFile(tfn) as zf:
        isbf = zf.open('build/scepclient-linux-amd64', 'r')
        osbf = open(SCEPCLIENT, "wb")
        while True:
            chunk = isbf.read(64 * 2**10)
            if not chunk:
                break
            osbf.write(chunk)
        isbf.close()
        osbf.close()
    os.unlink(tfn)
    os.chmod(SCEPCLIENT, stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def get_gce_instance_serial_number_and_uuid():
    req = urllib.request.Request("http://metadata.google.internal/computeMetadata/v1/instance/id",
                                 headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return "gcp-{}".format(resp.read().decode("utf-8")), None
    except urllib.error.URLError:
        return None, None


def get_dbus_serial_number_and_uuid():
    try:
        with open("/var/lib/dbus/machine-id", "r") as f:
            return "dbus-{}".format(f.read().strip()), None
    except IOError:
        return None, None


def get_serial_number_and_uuid():
    serial_number = uuid = None
    for func in (get_gce_instance_serial_number_and_uuid, get_dbus_serial_number_and_uuid):
        serial_number, uuid = func()
        if serial_number or uuid:
            break
    return serial_number, uuid


def get_ssl_context(client_cert=None, client_key=None):
    ctx = ssl.create_default_context(cafile=get_and_create_certificate_authority())
    if client_cert:
        ctx.load_cert_chain(client_cert, client_key)
    return ctx


def get_certificate_and_key_paths():
    return os.path.join(FILEBEAT_HOME, "client.crt"), os.path.join(FILEBEAT_HOME, "client.key")


def get_post_data(secret, serial_number, uuid):
    certificate, key = get_certificate_and_key_paths()
    return json.dumps({"secret": secret,
                       "serial_number": serial_number,
                       "uuid": uuid,
                       "certificate": certificate,
                       "key": key,
                       "certificate_authority": get_and_create_certificate_authority()}).encode("utf-8")


def start_enrollment(serial_number, uuid):
    print("START ENROLLMENT", ENROLLMENT_SECRET)
    req = urllib.request.Request(START_ENROLLMENT_URL,
                                 get_post_data(ENROLLMENT_SECRET, serial_number, uuid),
                                 DEFAULT_HEADERS)
    with urllib.request.urlopen(req, context=get_ssl_context()) as resp:
        return json.load(resp)


def build_csr(tmpdir, serial_number, cn, org, challenge):
    pkcs8_key = os.path.join(tmpdir, "client.key.pkcs8")
    cfg = {
        "req": {
            "default_bits": "2048",
            "default_md": "sha256",
            "default_keyfile": pkcs8_key,
            "encrypt_key": "no",
            "prompt": "no",
            "distinguished_name": "req_distinguished_name",
            "attributes": "req_attributes"
        },
        "req_distinguished_name": {
            "CN": cn.replace("$", "\\$"),
            "O": org.replace("$", "\\$"),
            "serialNumber": serial_number
        },
        "req_attributes": {
            "challengePassword": challenge,
        }
    }
    openssl_req_config = os.path.join(tmpdir, "openssl_req.cfg")
    with open(openssl_req_config, "w") as of:
        for section, section_body in cfg.items():
            of.write("[ {} ]\n".format(section))
            for key, val in section_body.items():
                of.write("{} = {}\n".format(key, val))
    csr = os.path.join(tmpdir, "csr.pem")  # expected csr file for scepclient
    subprocess.check_call([
        OPENSSL,
        "req", "-new",
        "-config", openssl_req_config,
        "-out", csr
    ])
    # convert key to pkcs1 for scepclient
    subprocess.check_call([
        OPENSSL,
        "rsa",
        "-in", pkcs8_key,
        "-out", os.path.join(tmpdir, "client.key")
    ])


def get_certificate(serial_number, cn, org, challenge, url):
    print("GET CERTIFICATE", cn, org, challenge, url)
    if not os.path.isdir(FILEBEAT_HOME):
        os.makedirs(FILEBEAT_HOME)
    old_umask = os.umask(0o077)
    old_dir = os.getcwd()
    tmpdir = tempfile.mkdtemp()
    os.chdir(tmpdir)
    build_csr(tmpdir, serial_number, cn, org, challenge)
    subprocess.check_call([
        SCEPCLIENT,
        "-server-url", url,
        "-private-key", "client.key",
        "-certificate", "client.crt"
    ])
    client_cert, private_key = get_certificate_and_key_paths()
    shutil.move("client.crt", client_cert)
    shutil.move("client.key", private_key)
    os.chdir(old_dir)
    shutil.rmtree(tmpdir)
    os.umask(old_umask)
    return client_cert, private_key


def complete_enrollment(client_cert, client_key, enrollment_session_secret, serial_number, uuid):
    print("COMPLETE ENROLLMENT", client_cert, client_key, enrollment_session_secret)
    req = urllib.request.Request(COMPLETE_ENROLLMENT_URL,
                                 get_post_data(enrollment_session_secret, serial_number, uuid),
                                 DEFAULT_HEADERS)
    with urllib.request.urlopen(req, context=get_ssl_context(client_cert, client_key)) as resp:
        resp_json = json.load(resp)
    with open(FILEBEAT_YML, "w") as f:
        f.write(resp_json["filebeat.yml"])


def restart_filebeat():
    subprocess.check_call([
        "systemctl", "restart", "filebeat",
    ])


def update_default_zentral_plist():
    config = configparser.ConfigParser()
    config["server"] = {"base_url": "https://%TLS_HOSTNAME%"}
    with open(os.path.join(get_and_create_zentral_dir(), "info.cfg"), "w") as of:
        config.write(of)


if __name__ == "__main__":
    prepare_default_headers()
    install_scepclient()
    install_filebeat()
    serial_number, uuid = get_serial_number_and_uuid()
    enrollment_session_data = start_enrollment(serial_number, uuid)
    client_cert, client_key = get_certificate(serial_number, **enrollment_session_data["scep"])
    complete_enrollment(client_cert, client_key, enrollment_session_data["secret"], serial_number, uuid)
    restart_filebeat()
    update_default_zentral_plist()
