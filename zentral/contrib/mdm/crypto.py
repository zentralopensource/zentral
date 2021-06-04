import os.path
import subprocess
import tempfile
from asn1crypto import cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID
from django.utils.functional import SimpleLazyObject
from zentral.conf import settings
from OpenSSL import crypto


# CA verification


IPHONE_DEVICE_CA_CN = "Apple iPhone Device CA"
IPHONE_DEVICE_CA_FULLCHAIN = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "assets",
    "Apple_iPhone_Device_CA_Fullchain.pem"
)


def verify_store_certificate(store, certificate_bytes):
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_bytes)
    store_ctx = crypto.X509StoreContext(store, certificate)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return False
    else:
        return True


def get_scep_ca_store():
    store = crypto.X509Store()
    head = "-----BEGIN CERTIFICATE-----"
    for tail in settings["apps"]["zentral.contrib.mdm"]["scep_ca_fullchain"].split(head)[1:]:
        certificate_bytes = (head + tail).encode("utf-8")
        store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, certificate_bytes))
    return store


SCEP_CA_STORE = SimpleLazyObject(get_scep_ca_store)


def verify_zentral_scep_ca_issuer(certificate_bytes):
    return verify_store_certificate(SCEP_CA_STORE, certificate_bytes)


def get_iphone_device_ca_store():
    store = crypto.X509Store()
    store.load_locations(IPHONE_DEVICE_CA_FULLCHAIN)
    store.set_flags(0x200000)  # TODO hack! see X509_V_FLAG_NO_CHECK_TIME, because one of the cert has expired!
    return store


IPHONE_DEVICE_CA_STORE = SimpleLazyObject(get_iphone_device_ca_store)


def verify_apple_iphone_device_ca_issuer(certificate_bytes):
    return verify_store_certificate(IPHONE_DEVICE_CA_STORE, certificate_bytes)


# CMS / PKCS7


def get_signer_certificate(content, signer):
    certificates = content["certificates"]
    signer_id = signer["sid"]
    for certificate in certificates:
        if certificate.chosen.serial_number == signer_id.chosen["serial_number"].native and \
           certificate.chosen.issuer == signer_id.chosen["issuer"]:
            certificate_bytes = certificate.dump()
            certificate = x509.load_der_x509_certificate(certificate_bytes)
            certificate_i_cn = ", ".join(
                o.value
                for o in certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            )
            return certificate_i_cn, certificate_bytes, certificate


def get_cryptography_hash_algorithm(signer):
    hash_name = signer["digest_algorithm"]["algorithm"].native
    if hash_name == "sha1":
        return hashes.SHA1
    elif hash_name == "sha256":
        return hashes.SHA256
    elif hash_name == "sha512":
        return hashes.SHA512
    else:
        raise ValueError("Unknown hash {}".format(hash_name))


def get_cryptography_asymmetric_padding(signer):
    padding_name = signer["signature_algorithm"].signature_algo
    if padding_name == "rsassa_pkcs1v15":
        return padding.PKCS1v15
    else:
        raise ValueError("Unknown padding {}".format(padding_name))


def verify_certificate_signature(certificate, signer, payload):
    public_key = certificate.public_key()
    signature = signer['signature'].native
    if "signed_attrs" in signer and signer["signed_attrs"]:
        # Seen with the iPhone simulator for example
        signed_string = signer["signed_attrs"].dump()
        if signed_string.startswith(b'\xa0'):
            # TODO: WTF!!!
            # see https://stackoverflow.com/questions/24567623/how-to-see-what-attributes-are-signed-inside-pkcs7#24581628  # NOQA
            signed_string = b'\x31' + signed_string[1:]
    else:
        signed_string = payload
    asymmetric_padding = get_cryptography_asymmetric_padding(signer)
    hash_algorithm = get_cryptography_hash_algorithm(signer)
    try:
        public_key.verify(signature, signed_string,
                          asymmetric_padding(), hash_algorithm())
    except InvalidSignature:
        return False
    else:
        return True


def verify_signed_payload(data):
    content_info = cms.ContentInfo.load(data)
    if content_info["content_type"].native != "signed_data":
        raise ValueError("Not signed data")
    content = content_info["content"]
    payload = content['encap_content_info']['content'].native
    certificates = []
    for signer in content["signer_infos"]:
        certificate_i_cn, certificate_bytes, certificate = get_signer_certificate(content, signer)
        if not verify_certificate_signature(certificate, signer, payload):
            raise ValueError("Invalid signature")
        certificates.append((certificate_i_cn, certificate_bytes, certificate))
    return certificates, payload


def verify_iphone_ca_signed_payload(data):
    certificates, payload = verify_signed_payload(data)
    for certificate_i_cn, certificate_bytes, certificate in certificates:
        if certificate_i_cn == IPHONE_DEVICE_CA_CN and verify_apple_iphone_device_ca_issuer(certificate_bytes):
            return payload
    raise ValueError("Untrusted CA")


def decrypt_cms_payload(payload, private_key_bytes):
    tmp_inkey_fd, tmp_inkey = tempfile.mkstemp()
    with os.fdopen(tmp_inkey_fd, "wb") as f:
        f.write(private_key_bytes)
    p = subprocess.Popen(["/usr/bin/openssl", "smime",  "-decrypt", "-inkey", tmp_inkey],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE)
    stdout, stderr = p.communicate(payload)
    os.unlink(tmp_inkey)
    return stdout


# PKCS12


def load_push_certificate(pkcs12_bytes, password=None):
    if password and isinstance(password, str):
        password = password.encode("utf-8")
    private_key, cert, _ = load_key_and_certificates(pkcs12_bytes, password)
    return {"certificate": cert.public_bytes(serialization.Encoding.PEM),
            "private_key": private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ),
            "not_before": cert.not_valid_before,
            "not_after": cert.not_valid_after,
            "topic": cert.subject.get_attributes_for_oid(NameOID.USER_ID)[0].value}
