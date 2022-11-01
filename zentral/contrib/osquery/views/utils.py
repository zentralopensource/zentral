from datetime import datetime
import logging
import uuid
from zentral.contrib.inventory.conf import (cleanup_windows_os_version,
                                            macos_version_from_build,
                                            windows_version_from_build)
from zentral.contrib.inventory.models import PrincipalUserSource
from zentral.contrib.osquery.models import FileCarvingSession
from zentral.utils.certificates import parse_text_dn


logger = logging.getLogger("zentral.contrib.osquery.views.utils")


def clean_dict(d, keys_to_keep=None):
    for k, v in list(d.items()):
        if keys_to_keep and k not in keys_to_keep:
            del d[k]
            continue
        if isinstance(v, str):
            v = v.replace("\u0000", "").strip()
        if v is None or v == "":
            del d[k]
        elif v != d[k]:
            d[k] = v
    return d


def update_os_version(tree, t):
    os_version = clean_dict(t, {"name", "major", "minor", "patch", "build"})
    for key in ("major", "minor", "patch"):
        value = os_version.get(key)
        if value and isinstance(value, str):
            try:
                os_version[key] = int(value)
            except ValueError:
                pass
    name = os_version.get("name")
    build = os_version.get("build")
    if name and build:
        name = name.lower()
        if "os x" in name:
            try:
                tree['os_version'] = macos_version_from_build(build)
            except ValueError:
                pass
            else:
                return
        elif "windows" in name:
            os_version = cleanup_windows_os_version(os_version)
    if os_version.get("major"):
        tree['os_version'] = os_version


def update_windows_build(tree, windows_build):
    current_build = windows_build.get("CurrentBuild")
    ubr = windows_build.get("UBR")
    if current_build and ubr:
        try:
            os_version = windows_version_from_build(f"{current_build}.{ubr}")
        except ValueError:
            logger.warning("Could not update Windows build: unknown build")
        else:
            tree['os_version'] = os_version
    else:
        logger.warning("Could not update Windows build: missing data")


def update_system_info(tree, t):
    system_info = clean_dict(
        t,
        {"computer_name", "hostname", "hardware_model", "hardware_serial",
         "cpu_type", "cpu_subtype", "cpu_brand", "cpu_physical_cores",
         "cpu_logical_cores", "physical_memory"}
    )
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


def update_ec2_instance_metadata(tree, t):
    ec2_instance_metadata = clean_dict(
        t,
        {"instance_id", "instance_type", "architecture", "region", "availability_zone",
         "local_hostname", "local_ipv4", "mac", "security_groups", "iam_arn", "ami_id",
         "reservation_id", "account_id", "ssh_public_key"}
    )
    if ec2_instance_metadata:
        tree["ec2_instance_metadata"] = ec2_instance_metadata


def collect_disk(disks, t):
    disk = clean_dict(t)
    if disk:
        if disk not in disks:
            disks.append(disk)
        else:
            logger.warning("Duplicated disk")


def collect_network_interface(network_interfaces, t):
    network_interface = clean_dict(t)
    if network_interface:
        if network_interface not in network_interfaces:
            network_interfaces.append(network_interface)
        else:
            logger.warning("Duplicated network interface")


def collect_deb_package(deb_packages, t):
    deb_package = clean_dict({
        k: t.get(k)
        for k in ("name", "version", "source", "size", "arch",
                  "revision", "status", "maintainer", "section", "priority")
    })
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


def collect_program_instance(program_instances, t):
    program = clean_dict(
        {k: t.pop(k, None)
         for k in ("name", "version", "language", "publisher", "identifying_number")}
    )
    program_instance = clean_dict(t)
    install_date = program_instance.pop("install_date", None)
    if install_date:
        try:
            program_instance["install_date"] = datetime.strptime(install_date, "%Y%m%d")
        except ValueError:
            logger.warning("Could not parse install date")
    if program and program_instance:
        program_instance["program"] = program
        if program_instance not in program_instances:
            program_instances.append(program_instance)
        else:
            logger.warning("Duplicated program instance")


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


def collect_ec2_instance_tag(ec2_instance_tags, t):
    ec2_instance_tag = clean_dict(t, {"key", "value"})
    if len(ec2_instance_tag) == 2:
        if ec2_instance_tag not in ec2_instance_tags:
            ec2_instance_tags.append(ec2_instance_tag)
        else:
            logger.warning("Duplicated EC2 instance tag")
    else:
        logger.warning("Invalid EC2 instance tag")


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


def update_tree_with_enrollment_host_details(tree, host_details):
    """
    apply the host details info to the machine snapshot tree
    """
    if host_details:
        os_version = host_details.get("os_version")
        if os_version:
            update_os_version(tree, os_version)
        system_info = host_details.get("system_info")
        if system_info:
            update_system_info(tree, system_info)


def update_tree_with_inventory_query_snapshot(tree, snapshot):
    """
    apply the result from the inventory snapshot tuples
    to the machine snapshot tree
    """
    deb_packages = []
    disks = []
    network_interfaces = []
    osx_app_instances = []
    program_instances = []
    principal_user = {}
    certificates = []
    ec2_instance_tags = []
    windows_build = {}
    for t in snapshot:
        table_name = t.pop('table_name')
        if table_name == 'os_version':
            update_os_version(tree, t)
        elif table_name == 'system_info':
            update_system_info(tree, t)
        elif table_name == 'uptime':
            update_system_uptime(tree, t)
        elif table_name == 'disks':
            collect_disk(disks, t)
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
        elif table_name == 'programs':
            collect_program_instance(program_instances, t)
        elif table_name == 'ec2_instance_metadata':
            update_ec2_instance_metadata(tree, t)
        elif table_name == 'ec2_instance_tags':
            collect_ec2_instance_tag(ec2_instance_tags, t)
        elif table_name == 'windows_build':
            windows_build_attr = clean_dict(t, {"name", "data"})
            windows_build[windows_build_attr["name"]] = windows_build_attr["data"]
    if deb_packages:
        tree["deb_packages"] = deb_packages
    if disks:
        tree["disks"] = disks
    if network_interfaces:
        tree["network_interfaces"] = network_interfaces
    if osx_app_instances:
        tree["osx_app_instances"] = osx_app_instances
    if program_instances:
        tree["program_instances"] = program_instances
    if principal_user:
        tree["principal_user"] = principal_user
    if certificates:
        tree["certificates"] = certificates
    if ec2_instance_tags:
        tree["ec2_instance_tags"] = ec2_instance_tags
    if windows_build:
        update_windows_build(tree, windows_build)


def prepare_file_carving_session_if_necessary(columns):
    carve = columns.get("carve")
    if carve != '1':
        return
    carve_guid = columns.get("carve_guid")
    if not carve_guid:
        return
    try:
        carve_guid = uuid.UUID(carve_guid)
    except (TypeError, ValueError):
        logger.error("Bad carve guid")
        return
    paths = []
    columns_path = columns.get("path")
    if isinstance(columns_path, str):
        paths = [p.strip() for p in columns_path.split(",")]
    return FileCarvingSession(
        id=uuid.uuid4(),
        carve_guid=carve_guid,
        paths=paths,
        carve_size=-1,
        block_size=-1,
        block_count=-1
    )
