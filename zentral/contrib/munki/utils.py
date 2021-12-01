from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID
from dateutil import parser
from django.utils.timezone import is_aware, make_naive
from .incidents import MunkiFailedInstallIncident, MunkiReinstallIncident, Severity
from .models import ManagedInstall


# machine snapshots


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


# managed install updates
# WARNING all this functions must be protected with a lock at the enrolled machine level


def create_managed_install_with_failed_install(
    serial_number,
    name, display_name, version,
    event_time,
    auto_failed_install_incidents
):
    mi, created = ManagedInstall.objects.get_or_create(
        machine_serial_number=serial_number,
        name=name,
        defaults={
            "display_name": display_name,
            "failed_at": event_time,
            "failed_version": version
        }
    )
    if created and auto_failed_install_incidents:
        yield MunkiFailedInstallIncident.build_incident_update(mi.name, mi.failed_version)


def create_managed_install_with_successful_install(
    serial_number,
    name, display_name, version,
    event_time
):
    ManagedInstall.objects.get_or_create(
        machine_serial_number=serial_number,
        name=name,
        defaults={"display_name": display_name, "installed_at": event_time, "installed_version": version}
    )


def delete_managed_install_with_successful_removal(
    mi,
    event_time,
    auto_failed_install_incidents,
    auto_reinstall_incidents
):
    if (
        auto_failed_install_incidents
        and mi.failed_at is not None
        and mi.failed_at < event_time
    ):
        yield MunkiFailedInstallIncident.build_incident_update(
            mi.name, mi.failed_version, Severity.NONE
        )
    if (
        auto_reinstall_incidents
        and mi.installed_at is not None
        and mi.installed_at < event_time
    ):
        yield MunkiReinstallIncident.build_incident_update(
            mi.name, mi.installed_version, Severity.NONE
        )
    mi.delete()


def update_managed_install_with_failed_install(
    mi,
    version,
    display_name,
    event_time,
    auto_failed_install_incidents
):
    if mi.failed_at is None or mi.failed_at < event_time:
        if auto_failed_install_incidents and mi.failed_at is not None and mi.failed_version != version:
            yield MunkiFailedInstallIncident.build_incident_update(
                mi.name, mi.failed_version, Severity.NONE
            )
        mi.display_name = display_name
        mi.failed_at = event_time
        mi.failed_version = version
        mi.save()
        if auto_failed_install_incidents:
            yield MunkiFailedInstallIncident.build_incident_update(
                mi.name, mi.failed_version
            )


def update_managed_install_with_successful_install(
    mi,
    version,
    display_name,
    event_time,
    auto_failed_install_incidents,
    auto_reinstall_incidents
):
    updated = False

    if mi.display_name != display_name:
        mi.display_name = display_name
        updated = True

    if mi.installed_at is None:
        mi.installed_at = event_time
        mi.installed_version = version
        updated = True
    elif mi.installed_at < event_time:
        mi.installed_at = event_time
        if mi.installed_version != version:
            # update installed version
            if mi.reinstall:
                # clear reinstall flag
                mi.reinstall = False
                if auto_reinstall_incidents:
                    yield MunkiReinstallIncident.build_incident_update(
                        mi.name, mi.installed_version, Severity.NONE
                    )
            mi.installed_version = version
            updated = True
        else:
            if not mi.reinstall:
                # set reinstall flage
                mi.reinstall = True
                updated = True
                if auto_reinstall_incidents:
                    yield MunkiReinstallIncident.build_incident_update(
                        mi.name, mi.installed_version
                    )

    if mi.failed_at is not None and mi.failed_at < event_time:
        # clear failed install
        if auto_failed_install_incidents:
            yield MunkiFailedInstallIncident.build_incident_update(
                mi.name, mi.failed_version, Severity.NONE
            )
        mi.failed_at = None
        mi.failed_version = None
        updated = True

    if updated:
        mi.save()


def update_managed_install_with_event(serial_number, event, event_time, configuration):
    # type
    event_type = event.get("type")
    if event_type not in ("install", "removal"):
        return
    name = event["name"]
    display_name = event["display_name"]
    version = event["version"]
    failed = int(event["status"]) != 0

    try:
        mi = ManagedInstall.objects.get(machine_serial_number=serial_number, name=name)
    except ManagedInstall.DoesNotExist:
        # create
        if event_type == "removal":
            # nothing to do
            return
        elif failed:
            yield from create_managed_install_with_failed_install(
                serial_number, name, display_name, version, event_time,
                configuration.auto_failed_install_incidents
            )
        else:
            create_managed_install_with_successful_install(
                serial_number, name, display_name, version, event_time
            )
    else:
        # update
        if (
            (mi.installed_at is not None and mi.installed_at > event_time)
            or (mi.failed_at is not None and mi.failed_at > event_time)
        ):
            # stalled event, nothing to update
            return

        if event_type == "removal":
            if not failed:
                yield from delete_managed_install_with_successful_removal(
                    mi, event_time,
                    configuration.auto_failed_install_incidents,
                    configuration.auto_reinstall_incidents
                )
        elif failed:
            yield from update_managed_install_with_failed_install(
                mi, version, display_name, event_time,
                configuration.auto_failed_install_incidents
            )
        else:
            yield from update_managed_install_with_successful_install(
                mi, version, display_name, event_time,
                configuration.auto_failed_install_incidents,
                configuration.auto_reinstall_incidents
            )


def apply_managed_installs(serial_number, managed_installs, configuration):
    existing_managed_installs = {
        mi.name: mi
        for mi in ManagedInstall.objects.select_for_update()
                                        .filter(machine_serial_number=serial_number)
    }

    # create or update existing managed installs
    for name, version, display_name, installed_at in managed_installs:
        # cleanup installed_at
        if isinstance(installed_at, str):
            installed_at = parser.parse(installed_at)
            if is_aware(installed_at):
                installed_at = make_naive(installed_at)

        try:
            mi = existing_managed_installs.pop(name)
        except KeyError:
            # create new managed install for this pkg
            ManagedInstall.objects.create(
                machine_serial_number=serial_number,
                name=name,
                display_name=display_name,
                installed_version=version,
                installed_at=installed_at
            )
        else:
            if installed_at is None:
                # we cannot do an update
                continue

            if mi.installed_at is not None and mi.installed_at > installed_at:
                # stalled update, nothing to do
                continue

            # eventually update the existing managed install
            update = False

            if mi.display_name != display_name:
                # update display name
                mi.display_name = display_name
                update = True

            if mi.failed_at is not None and mi.failed_at < installed_at:
                # clear failed install
                if configuration.auto_failed_install_incidents:
                    yield MunkiFailedInstallIncident.build_incident_update(
                        mi.name, mi.failed_version, Severity.NONE
                    )
                mi.failed_at = None
                mi.failed_version = None

            if version != mi.installed_version:
                if mi.reinstall:
                    # clear reinstall flag
                    mi.reinstall = False
                    if configuration.auto_reinstall_incidents:
                        yield MunkiReinstallIncident.build_incident_update(
                            mi.name, mi.installed_version, Severity.NONE
                        )

                mi.installed_version = version
                mi.installed_at = installed_at
                update = True
            else:
                if mi.installed_at is None:
                    mi.installed_at = installed_at
                    update = True
                elif not mi.reinstall:
                    # set reinstall flag
                    mi.reinstall = True
                    if configuration.auto_reinstall_incidents:
                        yield MunkiReinstallIncident.build_incident_update(
                            mi.name, mi.installed_version
                        )
                    update = True
            if update:
                mi.save()

    # delete not found stored managed installs
    for mi in existing_managed_installs.values():
        if mi.failed_at is not None and configuration.auto_failed_install_incidents:
            yield MunkiFailedInstallIncident.build_incident_update(
                mi.name, mi.failed_version, Severity.NONE
            )
        if mi.reinstall and configuration.auto_reinstall_incidents:
            yield MunkiReinstallIncident.build_incident_update(
                mi.name, mi.installed_version, Severity.NONE
            )
        mi.delete()
