from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID


def is_ca(certificate):
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
    cert_tree = {
        "valid_from": certificate.not_valid_before,
        "valid_until": certificate.not_valid_after,
        "signed_by": build_name_attributes_update_dict_from_name(certificate.issuer),
        "sha_1": certificate.fingerprint(hashes.SHA1()).hex()
    }
    cert_tree.update(build_name_attributes_update_dict_from_name(certificate.subject))
    return cert_tree


def iter_certificates(pem_certificates):
    default_backend_instance = default_backend()
    for pem_certificate in pem_certificates:
        yield x509.load_pem_x509_certificate(pem_certificate.encode("utf-8"), default_backend_instance)


def prepare_ms_tree_certificates(ms_tree):
    """
    filter and process the uploaded device pem certificates
    """
    pem_certificates = ms_tree.pop("pem_certificates", [])
    certificates = []
    for certificate in iter_certificates(pem_certificates):
        # filter out CA certificates
        if is_ca(certificate):
            continue
        # build the cert tree
        cert_tree = build_cert_tree(certificate)
        if cert_tree not in certificates:
            certificates.append(cert_tree)
    # update the ms tree
    if certificates:
        ms_tree["certificates"] = certificates
