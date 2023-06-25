import base64
import datetime
import json
import logging
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from dateutil import parser
from django.urls import reverse
from django.utils import timezone
from zentral.conf import settings
from zentral.utils.certificates import split_certificate_chain
from .crypto import decrypt_cms_payload
from .dep_client import DEPClient, DEPClientError
from .models import DEPDevice, DEPEnrollment


logger = logging.getLogger("zentral.contrib.mdm.dep")


def build_dep_token_certificate(dep_token):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'zentral-dep-token-{}'.format(dep_token.pk)),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'zentral'),
    ]))
    now = timezone.now()
    one_day = datetime.timedelta(days=1)
    builder = builder.not_valid_before(now - one_day)
    builder = builder.not_valid_after(now + 2 * one_day)
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(
        private_key=private_key, algorithm=hashes.SHA256(),
    )
    return certificate, private_key


def add_dep_token_certificate(dep_token):
    certificate, private_key = build_dep_token_certificate(dep_token)
    dep_token.certificate = certificate.public_bytes(serialization.Encoding.PEM)
    dep_token.set_private_key(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )
    dep_token.save()


def decrypt_dep_token(dep_token, payload):
    decrypted_payload = decrypt_cms_payload(payload, dep_token.get_private_key())
    message_lines = []
    found_tag = False
    for line in decrypted_payload.splitlines():
        line = line.decode("utf-8")
        if found_tag and line != "-----END MESSAGE-----":
            message_lines.append(line)
        if line == "-----BEGIN MESSAGE-----":
            found_tag = True
    return json.loads("".join(message_lines))


def serialize_dep_profile(dep_enrollment):
    payload = {"profile_name": dep_enrollment.name[:125],
               "url": "{}{}".format(
                   settings["api"]["tls_hostname"],
                   reverse("mdm_public:dep_enroll", args=(dep_enrollment.enrollment_secret.secret,))
               )}
    if dep_enrollment.pk:
        payload["devices"] = list(dep_enrollment.depdevice_set.values_list("serial_number", flat=True))
    else:
        payload["devices"] = []

    # do authentication in webview if a realm is present
    if dep_enrollment.realm:
        payload["configuration_web_url"] = "{}{}".format(
            settings["api"]["tls_hostname"],
            reverse("mdm_public:dep_web_enroll", args=(dep_enrollment.enrollment_secret.secret,))
        )

    # standard attibutes
    for attr in ("allow_pairing",
                 "auto_advance_setup",
                 "await_device_configured",
                 "is_mandatory",
                 "is_mdm_removable",
                 "is_multi_user",
                 "is_supervised",
                 "skip_setup_items"):
        payload[attr] = getattr(dep_enrollment, attr)

    # optional strings
    for attr in ("department",
                 "language",
                 "org_magic",
                 "region",
                 "support_phone_number",
                 "support_email_address",
                 ):
        val = getattr(dep_enrollment, attr)
        if val:
            val = val.strip()
            if val:
                payload[attr] = val

    # certificates
    if dep_enrollment.include_tls_certificates:
        anchor_certs = []
        for pem_data in split_certificate_chain(settings["api"]["tls_fullchain"]):
            certificate = x509.load_pem_x509_certificate(pem_data.encode("utf-8"))
            der_bytes = certificate.public_bytes(serialization.Encoding.DER)
            anchor_certs.append(base64.b64encode(der_bytes).decode("utf-8"))
        if anchor_certs:
            payload["anchor_certs"] = anchor_certs

    return payload


def dep_device_update_dict(device, known_enrollments=None):
    if known_enrollments is None:
        known_enrollments = {}
    update_d = {}

    # device attributes
    for attr in ("asset_tag",
                 "color",
                 "description",
                 "device_family",
                 "model",
                 "os"):
        update_d[attr] = device.get(attr) or ""

    # standard nullable attibutes
    for attr in ("device_assigned_by",
                 "profile_status",
                 "profile_uuid"):
        try:
            val = device[attr]
        except KeyError:
            pass
        else:
            if attr == "profile_uuid":
                val = uuid.UUID(val)
                enrollment = None
                try:
                    enrollment = known_enrollments[val]
                except KeyError:
                    try:
                        enrollment = DEPEnrollment.objects.get(uuid=val)
                    except DEPEnrollment.DoesNotExist:
                        logger.error("Unknown DEP profile %s", val)
                update_d["enrollment"] = enrollment
            update_d[attr] = val

    # datetime nullable attributes
    for attr in ("device_assigned_date",
                 "profile_assign_time",
                 "profile_push_time"):
        val = device.get(attr, None)
        if val:
            val = parser.parse(val)
        update_d[attr] = val

    return update_d


def sync_dep_virtual_server_devices(dep_virtual_server, force_fetch=False, assign_default_profile=True):
    dep_token = dep_virtual_server.token
    client = DEPClient.from_dep_token(dep_token)
    if force_fetch or not dep_token.sync_cursor:
        fetch = True
        devices = client.fetch_devices()
    else:
        fetch = False
        devices = client.sync_devices(dep_token.sync_cursor)

    known_enrollments = {e.uuid: e for e in dep_virtual_server.depenrollment_set.all()}

    found_serial_numbers = []
    unassigned_serial_numbers = []

    for device in devices:
        serial_number = device["serial_number"]
        found_serial_numbers.append(serial_number)
        defaults = {"virtual_server": dep_virtual_server}

        # default assignment
        if assign_default_profile and not device.get("profile_uuid") and dep_virtual_server.default_enrollment:
            unassigned_serial_numbers.append(serial_number)

        # sync
        if not fetch:
            op_type = device["op_type"]
            op_date = parser.parse(device["op_date"])
            if timezone.is_aware(op_date):
                op_date = timezone.make_naive(op_date)
            try:
                dep_device = DEPDevice.objects.get(serial_number=serial_number)
            except DEPDevice.DoesNotExist:
                dep_device = None
            if dep_device and dep_device.last_op_date and dep_device.last_op_date > op_date:
                # already applied a newer operation. skip stalled one.
                continue
            else:
                defaults["last_op_type"] = op_type
                defaults["last_op_date"] = op_date

        defaults.update(dep_device_update_dict(device, known_enrollments))

        yield DEPDevice.objects.update_or_create(serial_number=serial_number, defaults=defaults)
    dep_token.sync_cursor = devices.cursor
    dep_token.last_synced_at = timezone.now()
    dep_token.save()
    if fetch:
        # mark all other existing token devices as deleted
        (DEPDevice.objects.filter(virtual_server=dep_virtual_server)
                          .exclude(serial_number__in=found_serial_numbers)
                          .update(last_op_type=DEPDevice.OP_TYPE_DELETED))
    if unassigned_serial_numbers:
        # assign the default profile
        response = client.assign_profile(dep_virtual_server.default_enrollment.uuid, unassigned_serial_numbers)
        for serial_number, result in response.get("devices").items():
            if result != "SUCCESS":
                logger.error("Could not assign profile %s to device %s: %s",
                             dep_virtual_server.default_enrollment.uuid, serial_number, result)
        # fetch the updated records, avoid an infinite recursion!
        yield from sync_dep_virtual_server_devices(dep_virtual_server, assign_default_profile=False)


def assign_dep_device_profile(dep_device, dep_profile):
    dep_client = DEPClient.from_dep_virtual_server(dep_device.virtual_server)
    serial_number = dep_device.serial_number
    response = dep_client.assign_profile(dep_profile.uuid, [serial_number])
    try:
        result = response["devices"][serial_number]
    except KeyError:
        raise DEPClientError("Unknown client response structure")
    if result == "SUCCESS":
        # fetch a fresh device record and apply the updates
        updated_device = dep_client.get_devices([serial_number])[serial_number]
        for attr, val in dep_device_update_dict(updated_device).items():
            setattr(dep_device, attr, val)
        dep_device.save()
    else:
        err_msg = f"Could not assign profile {dep_profile.uuid} to device {serial_number}: {result}"
        logger.error(err_msg)
        raise DEPClientError(err_msg)


def add_dep_profile(dep_profile):
    dep_client = DEPClient.from_dep_virtual_server(dep_profile.virtual_server)
    profile_payload = serialize_dep_profile(dep_profile)
    profile_response = dep_client.add_profile(profile_payload)
    dep_profile.uuid = profile_response["profile_uuid"]
    dep_profile.save()

    success_devices = []
    not_accessible_devices = []
    failed_devices = []
    for serial_number, result in profile_response["devices"].items():
        if result == "SUCCESS":
            success_devices.append(serial_number)
        elif result == "NOT_ACCESSIBLE":
            not_accessible_devices.append(serial_number)
        elif result == "FAILED":
            failed_devices.append(serial_number)
        else:
            raise DEPClientError(f"Unknown result {serial_number}: {result}")

    if failed_devices:
        # TODO: implement retry
        raise DEPClientError("Failed devices!")

    # update dep devices
    if success_devices:
        # To avoid some performance issues, only update the devices in the database.
        # The next sync will fix the differences.
        (DEPDevice.objects.filter(serial_number__in=success_devices)
                          .update(profile_uuid=dep_profile.uuid,
                                  profile_assign_time=datetime.datetime.utcnow(),
                                  enrollment=dep_profile))

    # mark unaccessible devices as deleted
    if not_accessible_devices:
        (DEPDevice.objects.filter(serial_number__in=not_accessible_devices)
                          .update(last_op_type=DEPDevice.OP_TYPE_DELETED))


def refresh_dep_device(dep_device):
    dep_client = DEPClient.from_dep_virtual_server(dep_device.virtual_server)
    devices = dep_client.get_devices([dep_device.serial_number])
    if dep_device.serial_number not in devices:
        dep_device.last_op_type = DEPDevice.OP_TYPE_DELETED
        dep_device.save()
        raise DEPClientError("Could not find the device.")
    else:
        for attr, val in dep_device_update_dict(devices[dep_device.serial_number]).items():
            setattr(dep_device, attr, val)
        dep_device.save()
