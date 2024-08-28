from datetime import date, datetime, time, timedelta
import hashlib
import os.path
import plistlib
import uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
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
                                        SoftwareUpdate, SoftwareUpdateDeviceID, SoftwareUpdateEnforcement,
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


def force_realm_user(realm=None, username=None, email=None):
    if not realm:
        realm = force_realm()
    username = username or get_random_string(12)
    email = email or f"{username}@example.com"
    realm_user = RealmUser.objects.create(
        realm=realm,
        claims={"username": username,
                "email": email},
        username=username,
        email=email,
    )
    return realm, realm_user


# push certificate


def force_push_certificate_material(topic=None, reduced_key_size=True, encrypt_key=True, privkey_bytes=None):
    if privkey_bytes:
        privkey = serialization.load_pem_private_key(privkey_bytes, None)
    else:
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
    if encrypt_key:
        privkey_password = get_random_string(12).encode("utf-8")
        encryption_algorithm = serialization.BestAvailableEncryption(privkey_password)
    else:
        privkey_password = None
        encryption_algorithm = serialization.NoEncryption()
    privkey_pem = privkey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm,
    )
    return cert_pem, privkey_pem, privkey_password


def force_push_certificate(
    topic=None,
    with_material=False,
    reduced_key_size=True,
    commit=True,
    provisioning_uid=None,
):
    if topic is None:
        topic = get_random_string(12)
    name = get_random_string(12)
    if with_material:
        push_certificate = PushCertificate.objects.create(provisioning_uid=provisioning_uid, name=name)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material(topic, reduced_key_size)
        for k, v in load_push_certificate_and_key(cert_pem, privkey_pem, privkey_password).items():
            if k == "private_key":
                push_certificate.set_private_key(v)
            else:
                setattr(push_certificate, k, v)
    else:
        push_certificate = PushCertificate.objects.create(
            provisioning_uid=provisioning_uid,
            name=name,
            topic=topic,
            not_before=datetime(2000, 1, 1),
            not_after=datetime(2040, 1, 1),
            certificate=b"1",
        )
        push_certificate.set_private_key(b"2")
    if commit:
        push_certificate.save()
    return push_certificate


# SCEP config


def force_scep_config(provisioning_uid=None):
    scep_config = SCEPConfig(
        provisioning_uid=provisioning_uid,
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


def force_dep_enrollment(mbu, push_certificate=None, display_name=None):
    if push_certificate is None:
        push_certificate = force_push_certificate()
    return DEPEnrollment.objects.create(
        display_name=display_name or get_random_string(12),
        name=get_random_string(12),
        uuid=uuid.uuid4(),
        push_certificate=push_certificate,
        scep_config=force_scep_config(),
        virtual_server=force_dep_virtual_server(),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu),
        skip_setup_items=[k for k, _ in skippable_setup_panes],
    )


def force_ota_enrollment(mbu=None, realm=None, display_name=None):
    if mbu is None:
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
    return OTAEnrollment.objects.create(
        push_certificate=force_push_certificate(),
        scep_config=force_scep_config(),
        name=get_random_string(12),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu),
        realm=realm,
        display_name=display_name or get_random_string(12),
    )


def force_user_enrollment(mbu, realm=None, enrollment_display_name=None):
    return UserEnrollment.objects.create(
        push_certificate=force_push_certificate(),
        realm=realm or force_realm(),
        scep_config=force_scep_config(),
        name=get_random_string(12),
        enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=mbu),
        display_name=enrollment_display_name or get_random_string(12)
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
    realm_user_email=None,
    realm_user_username=None,
    enrollment_display_name=None,
):
    dep_enrollment = force_dep_enrollment(mbu, push_certificate, display_name=enrollment_display_name)
    if realm_user:
        dep_enrollment.use_realm_user = True
        dep_enrollment.username_pattern = DEPEnrollment.UsernamePattern.DEVICE_USERNAME
        dep_enrollment.save()
    if serial_number is None:
        serial_number = get_random_string(12)
    if device_udid is None:
        device_udid = str(uuid.uuid4())
    session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
        dep_enrollment, serial_number, device_udid
    )
    if realm_user:
        session.dep_enrollment.realm, session.realm_user = force_realm_user(email=realm_user_email,
                                                                            username=realm_user_username)
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


def force_recovery_password_config(rotation_interval_days=0, static_password=None, rotate_firmware_password=False):
    cfg = RecoveryPasswordConfig.objects.create(
        name=get_random_string(12),
        dynamic_password=static_password is None,
        rotation_interval_days=rotation_interval_days,
        rotate_firmware_password=rotate_firmware_password,
    )
    if static_password:
        cfg.set_static_password(static_password)
        cfg.save()
    return cfg


def force_software_update_enforcement(
    name=None,
    details_url="",
    platforms=["macOS"],
    os_version="",
    build_version="",
    local_datetime=None,
    max_os_version="",
    local_time=None,
    delay_days=None,
    tags=None,
):
    name = name or get_random_string(12)
    if not os_version:
        max_os_version = max_os_version or "17.1.2"
        local_time = local_time or time(9, 30)
        delay_days = delay_days or 14
    else:
        local_datetime = local_datetime or datetime.utcnow() + timedelta(days=30)
    sue = SoftwareUpdateEnforcement.objects.create(
        name=name,
        details_url=details_url,
        platforms=platforms,
        os_version=os_version,
        build_version=build_version,
        local_datetime=local_datetime,
        max_os_version=max_os_version,
        local_time=local_time,
        delay_days=delay_days,
    )
    if tags:
        sue.tags.set(tags)
    return sue


def force_software_update(
    device_id,
    version,
    posting_date,
    expiration_date=None,
    public=False,
    version_extra="",
    build="",
    prerequisite_build="",
    platform=Platform.MACOS,
):
    major, minor, patch = (int(i) for i in version.split("."))
    su = SoftwareUpdate.objects.create(
        platform=platform,
        public=public,
        major=major,
        minor=minor,
        patch=patch,
        availability=(posting_date, expiration_date),
        extra=version_extra,
        build=build,
        prerequisite_build=prerequisite_build,
    )
    SoftwareUpdateDeviceID.objects.create(software_update=su, device_id=device_id)
    return su


def force_blueprint(filevault_config=None, recovery_password_config=None, software_update_enforcement=None):
    bp = Blueprint.objects.create(
        name=get_random_string(12),
        filevault_config=filevault_config,
        recovery_password_config=recovery_password_config,
    )
    if software_update_enforcement:
        bp.software_update_enforcements.add(software_update_enforcement)
    return bp


def force_asset():
    return Asset.objects.create(
        adam_id=get_random_string(12),
        pricing_param=get_random_string(12),
        product_type=Asset.ProductType.APP,
        device_assignable=True,
        revocable=True,
        supported_platforms=["iOS", "macOS"]
    )


def force_location(name=None, organization_name=None):
    location = Location(
        server_token_hash=get_random_string(40, allowed_chars='abcdef0123456789'),
        server_token=get_random_string(12),
        server_token_expiration_date=date(2050, 1, 1),
        organization_name=organization_name or get_random_string(12),
        country_code="DE",
        library_uid=str(uuid.uuid4()),
        name=name or get_random_string(12),
        platform="enterprisestore",
        website_url="https://business.apple.com",
        mdm_info_id=uuid.uuid4(),
    )
    location.set_notification_auth_token()
    location.save()
    return location


def force_location_asset(asset=None, location=None):
    return LocationAsset.objects.create(
        asset=asset or force_asset(),
        location=location or force_location()
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
            filename = "{}.pkg".format(get_random_string(17))
            EnterpriseApp.objects.create(
                artifact_version=artifact_version,
                package_sha256=64 * "0",
                package_size=8,
                package=SimpleUploadedFile(name=filename, content=b"yolofomo"),
                filename=filename,
                product_id="{}.{}.{}".format(get_random_string(2), get_random_string(4), get_random_string(8)),
                product_version="17",
                manifest={"items": [{"assets": [{}]}]}
            )
        elif artifact_type == Artifact.Type.STORE_APP:
            StoreApp.objects.create(
                artifact_version=artifact_version,
                location_asset=force_location_asset(),
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


MACOS_14_CLIENT_CAPABILITIES = {
    'supported-features': {},
    'supported-payloads': {
        'declarations': {
            'activations': [
                'com.apple.activation.simple'
            ],
            'assets': ['com.apple.asset.credential.acme',
                       'com.apple.asset.credential.certificate',
                       'com.apple.asset.credential.identity',
                       'com.apple.asset.credential.scep',
                       'com.apple.asset.credential.userpassword',
                       'com.apple.asset.data',
                       'com.apple.asset.useridentity'],
            'configurations': ['com.apple.configuration.legacy',
                               'com.apple.configuration.legacy.interactive',
                               'com.apple.configuration.management.status-subscriptions',
                               'com.apple.configuration.management.test',
                               'com.apple.configuration.passcode.settings',
                               'com.apple.configuration.screensharing.connection',
                               'com.apple.configuration.screensharing.connection.group',
                               'com.apple.configuration.screensharing.host.settings',
                               'com.apple.configuration.security.certificate',
                               'com.apple.configuration.security.identity',
                               'com.apple.configuration.services.configuration-files',
                               'com.apple.configuration.softwareupdate.enforcement.specific'],
            'management': ['com.apple.management.organization-info',
                           'com.apple.management.properties',
                           'com.apple.management.server-capabilities']},
            'status-items': ['device.identifier.serial-number',
                             'device.identifier.udid',
                             'device.model.family',
                             'device.model.identifier',
                             'device.model.marketing-name',
                             'device.model.number',
                             'device.operating-system.build-version',
                             'device.operating-system.family',
                             'device.operating-system.marketing-name',
                             'device.operating-system.supplemental.build-version',
                             'device.operating-system.supplemental.extra-version',
                             'device.operating-system.version',
                             'diskmanagement.filevault.enabled',
                             'management.client-capabilities',
                             'management.declarations',
                             'screensharing.connection.group.unresolved-connection',
                             'security.certificate.list',
                             'services.background-task',
                             'softwareupdate.failure-reason',
                             'softwareupdate.install-reason',
                             'softwareupdate.install-state',
                             'softwareupdate.pending-version',
                             'test.array-value',
                             'test.boolean-value',
                             'test.dictionary-value',
                             'test.error-value',
                             'test.integer-value',
                             'test.real-value',
                             'test.string-value']},
    'supported-versions': ['1.0.0']
}


MACOS_13_CLIENT_CAPABILITIES = {
    'supported-features': {},
    'supported-payloads': {
        'declarations': {
            'activations': ['com.apple.activation.simple'],
            'assets': [],
            'configurations': ['com.apple.configuration.legacy',
                               'com.apple.configuration.legacy.interactive',
                               'com.apple.configuration.management.status-subscriptions',
                               'com.apple.configuration.management.test',
                               'com.apple.configuration.passcode.settings'],
            'management': ['com.apple.management.organization-info',
                           'com.apple.management.properties',
                           'com.apple.management.server-capabilities']},
            'status-items': ['device.identifier.serial-number',
                             'device.identifier.udid',
                             'device.model.family',
                             'device.model.identifier',
                             'device.model.marketing-name',
                             'device.operating-system.build-version',
                             'device.operating-system.family',
                             'device.operating-system.marketing-name',
                             'device.operating-system.supplemental.build-version',
                             'device.operating-system.supplemental.extra-version',
                             'device.operating-system.version',
                             'management.client-capabilities',
                             'management.declarations',
                             'test.array-value',
                             'test.boolean-value',
                             'test.dictionary-value',
                             'test.error-value',
                             'test.integer-value',
                             'test.real-value',
                             'test.string-value']},
            'supported-versions': ['1.0.0']
}
