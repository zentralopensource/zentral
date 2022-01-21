import ssl
from tempfile import NamedTemporaryFile
from cryptography.hazmat.primitives import serialization
from django.utils.crypto import get_random_string


def create_client_ssl_context(certdata=None, keydata=None, keydata_password=None, cadata=None):
    """Create a client SSL context

    certdata         -- PEM-encoded certificate (bytes or str)
    keydata          -- PEM-encoded key (bytes or str)
    keydata_password -- keydata password (bytes or str)
    cadata           -- PEM-encoded certificates (bytes or str) for server verification
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    # client cert authentication
    if certdata and keydata:
        # client cert & key cannot be loaded from memory using the stdlib
        # use a temporary file to store the encrypted key and cert
        # TODO fix when the Python API is available
        if isinstance(certdata, str):
            certdata = certdata.encode("ascii")
        if isinstance(keydata, str):
            keydata = keydata.encode("ascii")
        if isinstance(keydata_password, str):
            keydata_password = keydata_password.encode("utf-8")
        key = serialization.load_pem_private_key(keydata, password=keydata_password)
        tmp_key_pwd = get_random_string(length=42).encode("utf-8")
        tmp_keydata = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(tmp_key_pwd)
        )
        with NamedTemporaryFile() as tmp_cert_file:
            tmp_cert_file.write(tmp_keydata)
            tmp_cert_file.write(certdata)
            tmp_cert_file.flush()
            ctx.load_cert_chain(tmp_cert_file.name, password=tmp_key_pwd)
    elif certdata:
        raise ValueError("Missing keydata")
    elif keydata:
        raise ValueError("Missing certdata")

    # server certificate verification
    ctx.verify_mode = ssl.CERT_REQUIRED  # ← should be already set because of PROTOCOL_TLS_CLIENT
    ctx.check_hostname = True   # ← idem
    if cadata:
        if isinstance(cadata, bytes):
            # load_verify_locations interprets bytes data as DER-encoded certificates
            cadata = cadata.decode("ascii")
        ctx.load_verify_locations(cadata=cadata)
    else:
        ctx.load_default_certs()

    return ctx
