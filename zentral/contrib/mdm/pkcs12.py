import getpass
from dateutil import parser
from OpenSSL import crypto


def load_push_certificate(pkcs12_bytes, password=None):
    args = [pkcs12_bytes]
    if password:
        if isinstance(password, str):
            password.encode("utf-8")
        args.append(password)
    pkcs12 = crypto.load_pkcs12(*args)
    certificate = pkcs12.get_certificate()
    private_key = pkcs12.get_privatekey()
    return {"certificate": crypto.dump_certificate(crypto.FILETYPE_PEM, certificate),
            "private_key": crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key),
            "not_before": parser.parse(certificate.get_notBefore()),
            "not_after": parser.parse(certificate.get_notAfter()),
            "topic": dict(certificate.get_subject().get_components())[b"UID"].decode("utf-8")}


if __name__ == "__main__":
    import sys
    import pprint
    pprint.pprint(load_push_certificate(open(sys.argv[1], "rb").read(), getpass.getpass("p12 pwd? ")))
