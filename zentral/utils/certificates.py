from collections import defaultdict
import re
from asn1crypto.core import load as load_asn1
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


def split_certificate_chain(chain):
    pem_certificates = []
    current_lines = []
    for line in chain.splitlines():
        if "--BEGIN" in line:
            if current_lines:
                pem_certificates.append("\n".join(current_lines))
                current_lines = []
        current_lines.append(line)
    if current_lines:
        pem_certificates.append("\n".join(current_lines))
    return pem_certificates


# the way for example that the logstash filebeat input serializes the serialNumber of a client cert
SERIAL_NUMBER_OID = '2.5.4.5'
ASN1_ENCODED_STRING_RE = re.compile("^#(?P<bytes>(?:[0-9a-f][0-9a-f]){3,})$")


def parse_dn(dn):
    # TODO: poor man's DN parser
    d = {}
    current_attr = ""
    current_val = ""

    state = "ATTR"
    string_state = "NOT_ESCAPED"
    for c in dn:
        if c == "\\" and string_state == "NOT_ESCAPED":
            string_state = "ESCAPED"
        else:
            if string_state == "NOT_ESCAPED" and c in "=,":
                if c == "=":
                    state = "VAL"
                elif c == ",":
                    state = "ATTR"
                    if current_attr:
                        d[current_attr] = current_val
                    current_attr = current_val = ""
            else:
                if state == "ATTR":
                    current_attr += c
                elif state == "VAL":
                    current_val += c
                if string_state == "ESCAPED":
                    string_state = "NOT_ESCAPED"

    if current_attr:
        d[current_attr] = current_val

    # try to extract the serial number
    encoded_serial_number = d.get(SERIAL_NUMBER_OID)
    if encoded_serial_number:
        m = ASN1_ENCODED_STRING_RE.match(encoded_serial_number.lower())
        if m:
            try:
                d["serialNumber"] = str(load_asn1(bytes.fromhex(m.group("bytes"))))
            except Exception:
                pass
            else:
                d.pop(SERIAL_NUMBER_OID)
    return d


def parse_text_dn(dn):
    # TODO: poor man's DN parser
    d = defaultdict(list)
    current_attr = ""
    current_val = ""

    state = "ATTR"
    string_state = "NOT_ESCAPED"
    for c in dn:
        if c == "\\" and string_state == "NOT_ESCAPED":
            string_state = "ESCAPED"
        else:
            if string_state == "NOT_ESCAPED" and c in "=/":
                if c == "=":
                    state = "VAL"
                elif c == "/":
                    state = "ATTR"
                    if current_attr:
                        d[current_attr].append(current_val)
                    current_attr = current_val = ""
            else:
                if state == "ATTR":
                    current_attr += c
                elif state == "VAL":
                    current_val += c
                if string_state == "ESCAPED":
                    string_state = "NOT_ESCAPED"

    if current_attr:
        d[current_attr].append(current_val)
    return d


# Apple Developer ID


APPLE_DEV_ID_CN_RE = re.compile(r'^Developer ID Application: (?P<team_name>.+) \((?P<team_id>[0-9A-Z]+)\)$')
APPLE_DEV_ID_ISSUER_CN = "Developer ID Certification Authority"


def parse_apple_dev_id(cn):
    m = APPLE_DEV_ID_CN_RE.match(cn)
    if not m:
        raise ValueError("Not an Apple developer ID")
    return m.groups()


# Certificate info for inventory and GUI


def is_ca(certificate):
    """Test if a x509 Certificate is a CA certificate"""
    # TODO: test self signed if no extensions found
    extensions = certificate.extensions
    try:
        return extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS).value.ca
    except x509.ExtensionNotFound:
        try:
            return extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_cert_sign
        except x509.ExtensionNotFound:
            pass
    return False


def build_name_attributes_update_dict_from_name(name):
    """Return an inventory certificate tree update dict from a x509 Name"""
    update_dict = {}
    for oid, ztl_attr, is_list in ((NameOID.COMMON_NAME, "common_name", False),
                                   (NameOID.ORGANIZATION_NAME, "organization", False),
                                   (NameOID.ORGANIZATIONAL_UNIT_NAME, "organizational_unit", False),
                                   (NameOID.DOMAIN_COMPONENT, "domain", True)):
        name_attributes = name.get_attributes_for_oid(oid)
        if name_attributes:
            if is_list:
                value = ".".join(na.value for na in name_attributes[::-1])
            else:
                value = name_attributes[-1].value
            update_dict[ztl_attr] = value
    return update_dict


def build_cert_tree(certificate):
    """Return an inventory certificate tree from a x509 Certificate"""
    cert_tree = {
        "valid_from": certificate.not_valid_before,
        "valid_until": certificate.not_valid_after,
        "signed_by": build_name_attributes_update_dict_from_name(certificate.issuer),
        "sha_1": certificate.fingerprint(hashes.SHA1()).hex()
    }
    cert_tree.update(build_name_attributes_update_dict_from_name(certificate.subject))
    return cert_tree


def iter_certificates(pem_certificates):
    """Return a x509 Certificte iterator from a PEM encoded certificate chain"""
    for pem_certificate in split_certificate_chain(pem_certificates):
        if isinstance(pem_certificate, str):
            pem_certificate = pem_certificate.encode("ascii")
        yield x509.load_pem_x509_certificate(pem_certificate)


def iter_cert_trees(pem_certificates):
    """Return an inventory certificate tree iterator from a PEM encoded certificate chain"""
    for certificate in iter_certificates(pem_certificates):
        yield build_cert_tree(certificate)
