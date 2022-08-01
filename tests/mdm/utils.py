from datetime import datetime, timedelta
import hashlib
import uuid
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.mdm.models import (DEPEnrollment, DEPEnrollmentSession, DEPOrganization, DEPToken,
                                        DEPVirtualServer,
                                        OTAEnrollment,
                                        EnrolledDevice, PushCertificate, SCEPConfig,
                                        UserEnrollment)


def force_push_certificate():
    push_certificate = PushCertificate(
        name=get_random_string(12),
        topic=get_random_string(12),
        not_before="2000-01-01",
        not_after="2040-01-01",
        certificate=b"1",
    )
    push_certificate.set_private_key(b"2")
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


def force_dep_enrollment(mbu):
    return DEPEnrollment.objects.create(
        name=get_random_string(12),
        uuid=uuid.uuid4(),
        push_certificate=force_push_certificate(),
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


def force_dep_enrollment_session(mbu, authenticated=False, completed=False):
    dep_enrollment = force_dep_enrollment(mbu)
    serial_number = get_random_string(12)
    device_udid = str(uuid.uuid4())
    session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
        dep_enrollment, serial_number, device_udid
    )
    if authenticated:
        enrolled_device = EnrolledDevice.objects.create(
            udid=device_udid,
            enrollment_id=device_udid,
            serial_number=serial_number,
            push_certificate=session.get_enrollment().push_certificate,
            platform="macOS",
            cert_fingerprint=hashlib.sha256(get_random_string(12).encode("utf-8")).digest(),
            cert_not_valid_after=(datetime.utcnow() + timedelta(days=366))
        )
        session.set_authenticated_status(enrolled_device)
        if completed:
            enrolled_device, _ = EnrolledDevice.objects.update_or_create(
                udid=device_udid,
                defaults={
                    "push_magic": get_random_string(12),
                    "token": get_random_string(12).encode("utf-8"),
                }
            )
            session.set_completed_status(enrolled_device)
            session.refresh_from_db()
    return session, device_udid, serial_number


def complete_enrollment_session(session):
    if session.enrolled_device:
        # To avoid issues in the ReEnrollmentSessions status updates
        device_udid = session.enrolled_device.udid
        enrolled_device = session.enrolled_device
    else:
        if session.enrollment_secret.udids:
            device_udid = session.enrollment_secret.udids[0]
        else:
            device_udid = str(uuid.uuid4())
        if session.enrollment_secret.serial_numbers:
            serial_number = session.enrollment_secret.serial_numbers[0]
        else:
            serial_number = get_random_string(12)
        enrolled_device = EnrolledDevice.objects.create(
            udid=device_udid,
            enrollment_id=device_udid,
            serial_number=serial_number,
            push_certificate=session.get_enrollment().push_certificate,
            platform="MACOS",
            cert_fingerprint=hashlib.sha256(get_random_string(12).encode("utf-8")).digest(),
            cert_not_valid_after=(datetime.utcnow() + timedelta(days=366))
        )
    session.set_authenticated_status(enrolled_device)
    enrolled_device, _ = EnrolledDevice.objects.update_or_create(
        udid=device_udid,
        defaults={
            "push_magic": get_random_string(12),
            "token": get_random_string(12).encode("utf-8"),
        }
    )
    session.set_completed_status(enrolled_device)
