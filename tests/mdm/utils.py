from datetime import datetime, timedelta
import hashlib
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.mdm.crypto import load_push_certificate_and_key
from zentral.contrib.mdm.models import (DEPEnrollment, DEPEnrollmentSession, DEPOrganization, DEPToken,
                                        DEPVirtualServer, EnrolledDevice, EnrolledUser,
                                        OTAEnrollment, OTAEnrollmentSession,
                                        PushCertificate, SCEPConfig,
                                        UserEnrollment, UserEnrollmentSession)


def force_realm():
    return Realm.objects.create(
        name=get_random_string(12),
        backend="ldap",
        username_claim="username",
        email_claim="email"
    )


def force_realm_user():
    realm = force_realm()
    username = get_random_string(12)
    email = f"{username}@example.com"
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        email=email,
    )
    return realm, realm_user


def force_push_certificate_material(topic=None, reduced_key_size=True):
    privkey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=512 if reduced_key_size else 2048,
    )  # lgtm[py/weak-crypto-key]
    builder = x509.CertificateBuilder()
    name = get_random_string(12)
    if topic is None:
        topic = get_random_string(12)
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
        x509.NameAttribute(NameOID.USER_ID, topic),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ]))
    builder = builder.not_valid_before(datetime.today() - timedelta(days=1))
    builder = builder.not_valid_after(datetime.today() + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(privkey.public_key())
    cert = builder.sign(
        private_key=privkey, algorithm=hashes.SHA256(),
    )
    cert_pem = cert.public_bytes(
        encoding=serialization.Encoding.PEM
    )
    privkey_password = get_random_string(12).encode("utf-8")
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(privkey_password)
    )
    return cert_pem, privkey_pem, privkey_password


def force_push_certificate(topic=None, with_material=False, reduced_key_size=True, commit=True):
    if topic is None:
        topic = get_random_string(12)
    name = get_random_string(12)
    if with_material:
        push_certificate = PushCertificate(name=name)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic, reduced_key_size)
        for k, v in load_push_certificate_and_key(cert_pem, privkey_pem, privkey_password).items():
            if k == "private_key":
                push_certificate.set_private_key(v)
            else:
                setattr(push_certificate, k, v)
    else:
        push_certificate = PushCertificate(
            name=name,
            topic=topic,
            not_before="2000-01-01",
            not_after="2040-01-01",
            certificate=b"1",
        )
        push_certificate.set_private_key(b"2")
    if commit:
        push_certificate.save()
    return push_certificate


def force_scep_config():
    scep_config = SCEPConfig(
        name=get_random_string(12),
        url="https://example.com/{}".format(get_random_string(12)),
        challenge_type="STATIC",
        challenge_kwargs={"challenge": get_random_string(12)}
    )
    scep_config.set_challenge_kwargs({"challenge": get_random_string(12)})
    scep_config.save()
    return scep_config


def force_dep_virtual_server(server_uuid=None):
    dep_organization = DEPOrganization.objects.create(
        identifier=get_random_string(128),
        admin_id="{}@zentral.io".format(get_random_string(12)),
        name=get_random_string(12),
        email="{}@zentral.io".format(get_random_string(12)),
        phone=get_random_string(12),
        address=get_random_string(12),
        type=DEPOrganization.ORG,
        version=DEPOrganization.V2
    )
    dep_token = DEPToken.objects.create(
        certificate=get_random_string(12).encode("utf-8"),
    )
    return DEPVirtualServer.objects.create(
        name=get_random_string(12),
        uuid=server_uuid or uuid.uuid4(),
        organization=dep_organization,
        token=dep_token
    )


def force_dep_enrollment(mbu, push_certificate=None):
    if push_certificate is None:
        push_certificate = force_push_certificate()
    return DEPEnrollment.objects.create(
        name=get_random_string(12),
        uuid=uuid.uuid4(),
        push_certificate=push_certificate,
        scep_config=force_scep_config(),
        virtual_server=force_dep_virtual_server(),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu),
        skip_setup_items=[p for p, _ in DEPEnrollment.SKIPPABLE_SETUP_PANE_CHOICES],
    )


def force_ota_enrollment(mbu):
    return OTAEnrollment.objects.create(
        push_certificate=force_push_certificate(),
        scep_config=force_scep_config(),
        name=get_random_string(12),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu)
    )


def force_user_enrollment(mbu, realm):
    return UserEnrollment.objects.create(
        push_certificate=force_push_certificate(),
        realm=realm,
        scep_config=force_scep_config(),
        name=get_random_string(12),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu)
    )


def get_session_device_udid_and_serial_number(session):
    if session.enrolled_device:
        # To avoid issues in the ReEnrollmentSessions
        device_udid = session.enrolled_device.udid
        serial_number = session.enrolled_device.serial_number
    else:
        if session.enrollment_secret.udids:
            device_udid = session.enrollment_secret.udids[0]
        else:
            device_udid = str(uuid.uuid4())
        if session.enrollment_secret.serial_numbers:
            serial_number = session.enrollment_secret.serial_numbers[0]
        else:
            serial_number = get_random_string(12)
    return device_udid, serial_number


def authenticate_enrollment_session(session):
    device_udid, serial_number = get_session_device_udid_and_serial_number(session)
    if not session.enrolled_device:
        enrolled_device = EnrolledDevice.objects.create(
            udid=device_udid,
            enrollment_id=device_udid,
            serial_number=serial_number,
            push_certificate=session.get_enrollment().push_certificate,
            platform="macOS",
            cert_fingerprint=hashlib.sha256(get_random_string(12).encode("utf-8")).digest(),
            cert_not_valid_after=(datetime.utcnow() + timedelta(days=366))
        )
    else:
        # To avoid issues in the ReEnrollmentSessions
        enrolled_device = session.enrolled_device
    session.set_authenticated_status(enrolled_device)
    return device_udid, serial_number


def complete_enrollment_session(session):
    device_udid, serial_number = authenticate_enrollment_session(session)
    enrolled_device, _ = EnrolledDevice.objects.update_or_create(
        udid=device_udid,
        defaults={
            "push_magic": get_random_string(12),
            "token": get_random_string(12).encode("utf-8"),
        }
    )
    session.set_completed_status(enrolled_device)
    session.refresh_from_db()
    return device_udid, serial_number


def force_dep_enrollment_session(
    mbu,
    authenticated=False, completed=False,
    push_certificate=None,
    device_udid=None,
    serial_number=None,
    realm_user=False,
):
    dep_enrollment = force_dep_enrollment(mbu, push_certificate)
    if serial_number is None:
        serial_number = get_random_string(12)
    if device_udid is None:
        device_udid = str(uuid.uuid4())
    session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
        dep_enrollment, serial_number, device_udid
    )
    if realm_user:
        session.dep_enrollment.realm, session.realm_user = force_realm_user()
        session.dep_enrollment.use_realm_user = True
        session.dep_enrollment.save()
        session.save()
    if completed:
        complete_enrollment_session(session)
    elif authenticated:
        authenticate_enrollment_session(session)
    return session, device_udid, serial_number


def force_ota_enrollment_session(mbu, phase3=False, authenticated=False, completed=False):
    ota_enrollment = force_ota_enrollment(mbu)
    serial_number = get_random_string(12)
    device_udid = str(uuid.uuid4())
    session = OTAEnrollmentSession.objects.create_from_machine_info(
        ota_enrollment, serial_number, device_udid
    )
    if phase3 or authenticated or completed:
        session.set_phase3_status()
        if completed:
            complete_enrollment_session(session)
        elif authenticated:
            authenticate_enrollment_session(session)
    return session, device_udid, serial_number


def force_user_enrollment_session(mbu, authenticated=False, completed=False):
    realm, realm_user = force_realm_user()
    user_enrollment = force_user_enrollment(mbu, realm)
    session = UserEnrollmentSession.objects.create_from_user_enrollment(user_enrollment)
    session.set_account_driven_authenticated_status(realm_user)
    session.set_started_status()
    if completed:
        device_udid, serial_number = complete_enrollment_session(session)
    elif authenticated:
        device_udid, serial_number = authenticate_enrollment_session(session)
    else:
        device_udid = serial_number = None
    return session, device_udid, serial_number


def force_enrolled_user(enrolled_device):
    return EnrolledUser.objects.create(
        enrolled_device=enrolled_device,
        user_id=str(uuid.uuid4()),
        long_name=get_random_string(12),
        short_name=get_random_string(12),
        token=get_random_string(12).encode("utf-8")
    )
