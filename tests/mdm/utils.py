from datetime import date, datetime, timedelta
import hashlib
import os.path
import plistlib
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import EnrollmentSecret
from zentral.contrib.mdm.artifacts import update_blueprint_serialized_artifacts
from zentral.contrib.mdm.crypto import load_push_certificate_and_key
from zentral.contrib.mdm.models import (Artifact, ArtifactVersion, Asset,
                                        Blueprint, BlueprintArtifact,
                                        Channel, Platform,
                                        DEPDevice, DEPEnrollment, DEPEnrollmentSession, DEPOrganization, DEPToken,
                                        DEPVirtualServer, EnrolledDevice, EnrolledUser,
                                        EnterpriseApp, FileVaultConfig, Location, LocationAsset,
                                        OTAEnrollment, OTAEnrollmentSession,
                                        Profile, PushCertificate, RecoveryPasswordConfig, SCEPConfig,
                                        StoreApp,
                                        UserEnrollment, UserEnrollmentSession)
from zentral.contrib.mdm.skip_keys import skippable_setup_panes
from zentral.utils.payloads import sign_payload


# realm


def force_realm():
    return Realm.objects.create(
        name=get_random_string(12),
        backend="ldap",
        username_claim="username",
        email_claim="email"
    )


def force_realm_user(realm=None):
    if not realm:
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


# push certificate


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


# SCEP config


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


# DEP virtual server


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


# DEP device


def force_dep_device(
    server=None,
    device_family="iPhone",
    op_type=DEPDevice.OP_TYPE_ADDED,
    profile_status=DEPDevice.PROFILE_STATUS_EMPTY,
    enrollment=None,
    mbu=None,
):
    if server is None:
        server = force_dep_virtual_server()
    dep_device = DEPDevice(
        virtual_server=server,
        serial_number=get_random_string(10).upper(),
        asset_tag=get_random_string(12),
        device_assigned_by="support@zentral.com",
        device_assigned_date=datetime.utcnow(),
        last_op_type=op_type,
        last_op_date=datetime.utcnow(),
        profile_status=profile_status,
    )
    if device_family == "iPhone":
        dep_device.color = "SPACE GRAY"
        dep_device.description = "IPHONE X SPACE GRAY 64GB-ZDD"
        dep_device.device_family = device_family
        dep_device.model = "iPhone X"
        dep_device.os = "iOS"
    else:
        dep_device.color = "MIDNIGHT"
        dep_device.description = "MBA 13.6 MDN"
        dep_device.device_family = "Mac"
        dep_device.model = "MacBook Air"
        dep_device.os = "OSX"
    if profile_status != DEPDevice.PROFILE_STATUS_EMPTY:
        if enrollment is None:
            enrollment = force_dep_enrollment(mbu)
        dep_device.enrollment = enrollment
        dep_device.profile_uuid = dep_device.enrollment.uuid
        dep_device.profile_assign_time = datetime.utcnow()
    dep_device.save()
    return dep_device


# enrollments


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
        skip_setup_items=[k for k, _ in skippable_setup_panes],
    )


def force_ota_enrollment(mbu, realm=None):
    return OTAEnrollment.objects.create(
        push_certificate=force_push_certificate(),
        scep_config=force_scep_config(),
        name=get_random_string(12),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu),
        realm=realm,
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


def force_ota_enrollment_session(mbu, phase3=False, authenticated=False, completed=False, realm_user=False):
    ota_enrollment = force_ota_enrollment(mbu)
    serial_number = get_random_string(12)
    device_udid = str(uuid.uuid4())
    session = OTAEnrollmentSession.objects.create_from_machine_info(
        ota_enrollment, serial_number, device_udid
    )
    if realm_user:
        session.ota_enrollment.realm, session.realm_user = force_realm_user()
        session.ota_enrollment.save()
        session.save()
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


# profiles


def build_payload(
    channel=None,
    payload_id=None,
    payload_uuid=None,
    missing_payload_id=False,
    missing_payload_uuid=False,
    payload_scope=None,
):
    payload = plistlib.load(
        open(os.path.join(os.path.dirname(__file__),
                          "testdata/test.mobileconfig"),
             "rb")
    )
    if channel == Channel.DEVICE:
        payload["PayloadScope"] = "System"
    elif channel == Channel.USER:
        payload["PayloadScope"] = "User"
    if payload_id:
        payload["PayloadIdentifier"] = payload_id
    if payload_uuid:
        payload["PayloadUUID"] = payload_uuid
    if missing_payload_id:
        payload.pop("PayloadIdentifier")
    if missing_payload_uuid:
        payload.pop("PayloadUUID")
    if payload_scope:
        payload["PayloadScope"] = payload_scope
    return payload


def build_mobileconfig_data(
    channel=None,
    payload_uuid=None,
    missing_payload_id=False,
    missing_payload_uuid=False,
    payload_scope=None,
    signed=False
):
    payload = build_payload(
        channel=channel,
        payload_uuid=payload_uuid,
        missing_payload_id=missing_payload_id,
        missing_payload_uuid=missing_payload_uuid,
        payload_scope=payload_scope,
    )
    data = plistlib.dumps(payload)
    if signed:
        data = sign_payload(data)
    return data


# artifacts


def force_filevault_config(prk_rotation_interval_days=0):
    return FileVaultConfig.objects.create(
        name=get_random_string(12),
        escrow_location_display_name=get_random_string(12),
        prk_rotation_interval_days=prk_rotation_interval_days
    )


def force_recovery_password_config(rotation_interval_days=0, static_password=None):
    cfg = RecoveryPasswordConfig.objects.create(
        name=get_random_string(12),
        dynamic_password=static_password is None,
        rotation_interval_days=rotation_interval_days,
    )
    if static_password:
        cfg.set_static_password(static_password)
        cfg.save()
    return cfg


def force_blueprint(filevault_config=None, recovery_password_config=None):
    return Blueprint.objects.create(
        name=get_random_string(12),
        filevault_config=filevault_config,
        recovery_password_config=recovery_password_config,
    )


def force_artifact(
    version_count=1,
    artifact_type=Artifact.Type.PROFILE,
    channel=Channel.DEVICE,
    platforms=None,
    install_during_setup_assistant=False,
    auto_update=True,
    requires=None,
):
    if platforms is None:
        platforms = [Platform.MACOS]
    artifact = Artifact.objects.create(
        name=get_random_string(12),
        type=artifact_type,
        channel=channel,
        platforms=platforms,
        install_during_setup_assistant=install_during_setup_assistant,
        auto_update=auto_update,
    )
    if requires:
        if not isinstance(requires, list):
            requires = [requires]
        artifact.requires.set(requires)
    artifact_versions = []
    for version in range(version_count, 0, -1):
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact,
            version=version,
            macos=True,
        )
        artifact_versions.append(artifact_version)
        if artifact_type == Artifact.Type.PROFILE:
            payload_identifier = "{}.{}.{}".format(get_random_string(2),
                                                   get_random_string(4),
                                                   str(uuid.uuid4()).upper())
            payload_uuid = str(uuid.uuid4()).upper()
            payload_display_name = get_random_string(16)
            payload_description = get_random_string(32)
            Profile.objects.create(
                artifact_version=artifact_version,
                source=plistlib.dumps(
                    {
                        "PayloadContent": [],
                        "PayloadDisplayName": payload_display_name,
                        "PayloadDescription": payload_description,
                        "PayloadIdentifier": payload_identifier,
                        "PayloadScope": "System" if channel == Channel.DEVICE else "User",
                        "PayloadRemovalDisallowed": False,
                        "PayloadType": "Configuration",
                        "PayloadUUID": payload_uuid,
                        "PayloadVersion": 1,
                    }
                ),
                payload_identifier=payload_identifier,
                payload_uuid=payload_uuid,
                payload_display_name=payload_display_name,
                payload_description=payload_description
            )
        elif artifact_type == Artifact.Type.ENTERPRISE_APP:
            EnterpriseApp.objects.create(
                artifact_version=artifact_version,
                filename="{}.pkg".format(get_random_string(17)),
                product_id="{}.{}.{}".format(get_random_string(2), get_random_string(4), get_random_string(8)),
                product_version="17",
                manifest={"items": [{"assets": [{}]}]}
            )
        elif artifact_type == Artifact.Type.STORE_APP:
            asset = Asset.objects.create(
                adam_id="1234567890",
                pricing_param="STDQ",
                product_type=Asset.ProductType.APP,
                device_assignable=True,
                revocable=True,
                supported_platforms=[Platform.MACOS]
            )
            location = Location(
                server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
                server_token=get_random_string(12),
                server_token_expiration_date=date(2050, 1, 1),
                organization_name=get_random_string(12),
                country_code="DE",
                library_uid=str(uuid.uuid4()),
                name=get_random_string(12),
                platform="enterprisestore",
                website_url="https://business.apple.com",
                mdm_info_id=uuid.uuid4(),
            )
            location.set_notification_auth_token()
            location.save()
            location_asset = LocationAsset.objects.create(
                asset=asset,
                location=location
            )
            StoreApp.objects.create(
                artifact_version=artifact_version,
                location_asset=location_asset
            )
    return artifact, artifact_versions


def force_blueprint_artifact(
    version_count=1,
    artifact_type=Artifact.Type.PROFILE,
    channel=Channel.DEVICE,
    platforms=None,
    install_during_setup_assistant=False,
    auto_update=True,
    requires=None,
    blueprint=None,
):
    artifact, artifact_versions = force_artifact(
        version_count,
        artifact_type,
        channel,
        platforms,
        install_during_setup_assistant,
        auto_update,
        requires,
    )
    if not blueprint:
        blueprint = force_blueprint()
    pf_kwargs = {pf.name.lower(): True for pf in artifact.platforms}
    blueprint_artifact, _ = BlueprintArtifact.objects.get_or_create(
        blueprint=blueprint,
        artifact=artifact,
        defaults=pf_kwargs,
    )
    update_blueprint_serialized_artifacts(blueprint)
    return blueprint_artifact, artifact, artifact_versions
