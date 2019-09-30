from datetime import datetime
import logging
from zentral.contrib.inventory.models import PrincipalUserSource
from zentral.utils.certificates import parse_text_dn


logger = logging.getLogger("zentral.contrib.osquery.views.utils")


def clean_dict(d):
    for k, v in list(d.items()):
        if isinstance(v, str):
            v = v.strip()
        if v is None or v == "":
            del d[k]
        elif v != d[k]:
            d[k] = v
    return d


def update_os_version(tree, t):
    os_version = clean_dict(t)
    if os_version:
        tree['os_version'] = os_version


def update_system_info(tree, t):
    system_info = clean_dict(t)
    if system_info:
        tree['system_info'] = system_info


def update_system_uptime(tree, t):
    try:
        system_uptime = int(t['total_seconds'])
    except (KeyError, TypeError, ValueError):
        pass
    else:
        if system_uptime > 0:
            tree['system_uptime'] = system_uptime


def collect_network_interface(network_interfaces, t):
    network_interface = clean_dict(t)
    if network_interface:
        if network_interface not in network_interfaces:
            network_interfaces.append(network_interface)
        else:
            logger.warning("Duplicated network interface")


def collect_deb_package(deb_packages, t):
    deb_package = clean_dict(t)
    if deb_package:
        if deb_package not in deb_packages:
            deb_packages.append(deb_package)
        else:
            logger.warning("Duplicated deb package")


def collect_osx_app_instance(osx_app_instances, t):
    bundle_path = t.pop('bundle_path')
    osx_app = clean_dict(t)
    if osx_app and bundle_path:
        osx_app_instance = {'app': osx_app,
                            'bundle_path': bundle_path}
        if osx_app_instance not in osx_app_instances:
            osx_app_instances.append(osx_app_instance)
        else:
            logger.warning("Duplicated osx app instance")


def collect_principal_user(principal_user, t):
    # TODO: verify only one principal user !
    principal_user_source = principal_user.setdefault("source", {"type": PrincipalUserSource.COMPANY_PORTAL})
    key = t.get("key")
    value = t.get("value")
    pu_key = None
    pu_src_prop_key = None
    if key == "aadUniqueId":
        pu_key = "unique_id"
    elif key == "aadUserId":
        pu_key = "principal_name"
    elif key == "version":
        pu_src_prop_key = "version"
    elif key == "aadAuthorityUrl" and value:
        pu_src_prop_key = "azure_ad_authority_url"
    if value:
        if pu_key:
            principal_user[pu_key] = value
        elif pu_src_prop_key:
            principal_user_source.setdefault("properties", {})[pu_src_prop_key] = value


def get_dn_value_from_dn_d(dn_d, attr):
    try:
        return dn_d[attr][-1]
    except (KeyError, IndexError):
        pass


def get_domain_from_dn_d(dn_d):
    domain = None
    dc_list = dn_d.get("DC")
    if dc_list:
        domain = ".".join(dc_list[::-1])
    return domain


def collect_certificate(certificates, t):
    subject_d = parse_text_dn(t["subject"])
    issuer_d = parse_text_dn(t["issuer"])

    certificates.append({
        "common_name": get_dn_value_from_dn_d(subject_d, "CN"),
        "organization": get_dn_value_from_dn_d(subject_d, "O"),
        "organizational_unit": get_dn_value_from_dn_d(subject_d, "OU"),
        "domain": get_domain_from_dn_d(subject_d),
        "sha_1": t["sha1"],
        "valid_from": datetime.utcfromtimestamp(int(t["not_valid_before"])),
        "valid_until": datetime.utcfromtimestamp(int(t["not_valid_after"])),
        "signed_by": {
            "common_name": get_dn_value_from_dn_d(issuer_d, "CN"),
            "organization": get_dn_value_from_dn_d(issuer_d, "O"),
            "organizational_unit": get_dn_value_from_dn_d(issuer_d, "OU"),
            "domain": get_domain_from_dn_d(issuer_d)
        }
    })


def update_tree_with_inventory_query_snapshot(tree, snapshot):
    """
    apply the result from the inventory snapshot tuples
    to the machine snapshot tree
    """
    deb_packages = []
    network_interfaces = []
    osx_app_instances = []
    principal_user = {}
    certificates = []
    for t in snapshot:
        table_name = t.pop('table_name')
        if table_name == 'os_version':
            update_os_version(tree, t)
        elif table_name == 'system_info':
            update_system_info(tree, t)
        elif table_name == 'uptime':
            update_system_uptime(tree, t)
        elif table_name == 'network_interface':
            collect_network_interface(network_interfaces, t)
        elif table_name == 'deb_packages':
            collect_deb_package(deb_packages, t)
        elif table_name == 'apps':
            collect_osx_app_instance(osx_app_instances, t)
        elif table_name == 'company_portal':
            collect_principal_user(principal_user, t)
        elif table_name == 'certificates':
            collect_certificate(certificates, t)
    if deb_packages:
        tree["deb_packages"] = deb_packages
    if network_interfaces:
        tree["network_interfaces"] = network_interfaces
    if osx_app_instances:
        tree["osx_app_instances"] = osx_app_instances
    if principal_user:
        tree["principal_user"] = principal_user
    if certificates:
        tree["certificates"] = certificates
