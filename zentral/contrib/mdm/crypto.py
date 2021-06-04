import os.path
import subprocess
import tempfile
from asn1crypto import cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto
from .conf import SCEP_CA_FULLCHAIN


APPLE_PKI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Apple_PKI")
IPHONE_CA_CN = "Apple iPhone Device CA"
IPHONE_CA_FULLCHAIN = os.path.join(APPLE_PKI_DIR, "Apple_iPhone_Device_CA_Fullchain.pem")


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


def get_openssl_version():
    cp = subprocess.run(["/usr/bin/openssl", "version"], capture_output=True)
    major, minor, patch = cp.stdout.decode("utf-8").split()[1].split(".")
    major = int(major)
    minor = int(minor)
    try:
        patch = int(patch)
    except ValueError:
        patch_number, patch_letter = patch[:-1], patch[-1]
        return (major, minor, int(patch_number), patch_letter)
    else:
        return (major, minor, patch)


def verify_ca_issuer_openssl(ca_fullchain, certificate_bytes, strict=True):
    args = ["/usr/bin/openssl", "verify"]
    openssl_version = get_openssl_version()
    if not strict and openssl_version >= (1, 1):
        args.append("-no_check_time")
    args.extend(["-CAfile", ca_fullchain])
    p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_bytes)
    stdout, stderr = p.communicate(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
    for line in stdout.splitlines():
        if strict and "error" in line.lower():
            return False
        if b'OK' in line:
            return True
    return False


def verify_apple_iphone_device_ca_issuer_openssl(certificate_bytes):
    # only check the chain, no expiration !!!
    return verify_ca_issuer_openssl(IPHONE_CA_FULLCHAIN, certificate_bytes, strict=False)


def verify_zentral_scep_ca_issuer_openssl(certificate_bytes):
    return verify_ca_issuer_openssl(SCEP_CA_FULLCHAIN, certificate_bytes, strict=False)


def get_apple_pki_store():
    store = crypto.X509Store()
    # add apple CA
    for filename in ("Apple_iPhone_Device_CA.pem",
                     "Apple_iPhone_Certification_Authority.pem",
                     "Apple_Root_CA.pem"):
        with open(os.path.join(APPLE_PKI_DIR, filename), "rb") as f:
            store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, f.read()))
    return store


APPLE_PKI_STORE = get_apple_pki_store()


def verify_apple_iphone_device_ca_issuer_pyopenssl(certificate_bytes):
    certificate = crypto.load_certificate(crypto.FILETYPE_ASN1, certificate_bytes)
    store_ctx = crypto.X509StoreContext(APPLE_PKI_STORE, certificate)
    try:
        store_ctx.verify_certificate()
    except crypto.X509StoreContextError:
        return False
    else:
        return True


def get_signer_certificate(content, signer):
    certificates = content["certificates"]
    signer_id = signer["sid"]
    for certificate in certificates:
        if certificate.chosen.serial_number == signer_id.chosen["serial_number"].native and \
           certificate.chosen.issuer == signer_id.chosen["issuer"]:
            certificate_bytes = certificate.dump()
            certificate = x509.load_der_x509_certificate(certificate_bytes, default_backend())
            certificate_i_cn = ", ".join(
                o.value
                for o in certificate.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
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
        if certificate_i_cn == IPHONE_CA_CN and verify_apple_iphone_device_ca_issuer_openssl(certificate_bytes):
            return payload
    raise ValueError("Untrusted CA")


if __name__ == "__main__":
    import sys
    with open(sys.argv[1], "rb") as f:
        certificates, payload = verify_signed_payload(f.read())
        for certificate_i_cn, certificate_bytes, certificate in certificates:
            print("ISSUER", certificate_i_cn)
            print("VERIFY WITH OPENSSL",
                  verify_apple_iphone_device_ca_issuer_openssl(certificate_bytes))
            print("VERIFY WITH PYOPENSSL",
                  verify_apple_iphone_device_ca_issuer_pyopenssl(certificate_bytes))
