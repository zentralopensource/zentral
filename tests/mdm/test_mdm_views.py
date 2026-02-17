import base64
import io
import json
import plistlib
import uuid
import zipfile
from datetime import date, datetime, time, timedelta
from unittest.mock import Mock, patch
from urllib.parse import quote
from uuid import uuid4

import asn1crypto.cms
import asn1crypto.util
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from realms.models import RealmGroup, RealmUserGroupMembership

from zentral.contrib.inventory.models import MachineTag, MetaBusinessUnit, Tag
from zentral.contrib.mdm.apps_books import get_otf_association_cache_key
from zentral.contrib.mdm.artifacts import Target, update_blueprint_serialized_artifacts
from zentral.contrib.mdm.commands import (
    CustomCommand,
    DeviceLock,
    InstallEnterpriseApplication,
)
from zentral.contrib.mdm.commands.base import load_command
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.declarations import (
    dump_cert_asset_token,
    dump_data_asset_token,
    dump_legacy_profile_token,
    load_cert_asset_token,
    load_data_asset_token,
    load_legacy_profile_token,
)
from zentral.contrib.mdm.events import (
    DeviceLockPinClearedEvent,
    MDMRequestEvent,
)
from zentral.contrib.mdm.models import (
    Artifact,
    ArtifactVersion,
    Blueprint,
    BlueprintArtifact,
    Channel,
    Command,
    DEPEnrollmentSession,
    DeviceAssignment,
    DeviceCommand,
    EnrolledDevice,
    OTAEnrollmentSession,
    Platform,
    Profile,
    RealmGroupTagMapping,
    ReEnrollmentSession,
    TargetArtifact,
    UserEnrollmentSession,
)

from .utils import (
    MACOS_14_CLIENT_CAPABILITIES,
    build_status_report,
    force_artifact,
    force_blueprint_artifact,
    force_dep_enrollment_session,
    force_enrolled_user,
    force_location,
    force_ota_enrollment_session,
    force_software_update,
    force_software_update_enforcement,
    force_user_enrollment_session,
)


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
)
@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class MDMViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # utility methods

    def _call(
        self,
        method,
        url,
        payload,
        session=None,
        serial_number=None,
        att_serial_number=None,
        att_udid=None,
        sign_message=False,
        bad_signature=False,
    ):
        kwargs = {}
        if payload:
            kwargs["data"] = plistlib.dumps(payload)
        if session:
            secret = session.enrollment_secret.secret
            if serial_number is None:
                serial_number = session.enrollment_secret.serial_numbers[0]
            if isinstance(session, DEPEnrollmentSession):
                enrollment_type = "DEP"
            elif isinstance(session, OTAEnrollmentSession):
                enrollment_type = "OTA"
            elif isinstance(session, ReEnrollmentSession):
                enrollment_type = "RE"
            else:
                enrollment_type = "USER"
            cn = f"MDM${enrollment_type}${secret}"
            o = f"MBU${self.mbu.pk}"
            with patch(
                "cryptography.hazmat.primitives.asymmetric.rsa._verify_rsa_parameters"
            ) as _verify_rsa_parameters:
                _verify_rsa_parameters.return_value = True
                privkey = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=512,  # faster
                )
            builder = x509.CertificateBuilder()
            subj_name_attrs = [
                x509.NameAttribute(NameOID.COMMON_NAME, cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
                x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
            ]
            if att_serial_number:
                subj_name_attrs.append(
                    x509.NameAttribute(
                        x509.ObjectIdentifier("1.2.840.113635.100.8.9.1"),
                        att_serial_number,
                    )
                )
            if att_udid:
                subj_name_attrs.append(
                    x509.NameAttribute(
                        x509.ObjectIdentifier("1.2.840.113635.100.8.9.2"), att_udid
                    )
                )
            builder = builder.subject_name(x509.Name(subj_name_attrs))
            builder = builder.issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(NameOID.COMMON_NAME, cn),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, o),
                        x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
                    ]
                )
            )
            builder = builder.not_valid_before(datetime.today() - timedelta(days=1))
            builder = builder.not_valid_after(datetime(2034, 5, 6))
            builder = builder.serial_number(x509.random_serial_number())
            builder = builder.public_key(privkey.public_key())
            cert = builder.sign(
                private_key=privkey,
                algorithm=hashes.SHA256(),
            )
            if not sign_message:
                # include the headers, like a mTLS proxy would be configured to do
                kwargs["HTTP_X_SSL_CLIENT_S_DN"] = (
                    f"serialNumber={serial_number},CN={cn},O={o}"
                )
                kwargs["HTTP_X_SSL_CLIENT_CERT"] = quote(
                    cert.public_bytes(encoding=serialization.Encoding.PEM)
                )
            else:
                # include the signature of the payload as MDM-Signature header
                sd = asn1crypto.cms.SignedData()
                sd["version"] = "v1"
                sd["encap_content_info"] = asn1crypto.util.OrderedDict(
                    [("content_type", "data"), ("content", None)]
                )
                sd["digest_algorithms"] = [
                    asn1crypto.util.OrderedDict(
                        [("algorithm", "sha1"), ("parameters", None)]
                    )
                ]
                cert = asn1crypto.x509.Certificate.load(
                    cert.public_bytes(encoding=serialization.Encoding.DER)
                )
                sd["certificates"] = [cert]
                si = asn1crypto.cms.SignerInfo()
                si["version"] = sd["version"]
                si["digest_algorithm"] = asn1crypto.util.OrderedDict(
                    [("algorithm", "sha1"), ("parameters", None)]
                )
                si["signature_algorithm"] = asn1crypto.util.OrderedDict(
                    [("algorithm", "sha1_rsa"), ("parameters", None)]
                )
                si["signature"] = privkey.sign(
                    kwargs.get("data", b"") if not bad_signature else b"yolo",
                    padding.PKCS1v15(),
                    hashes.SHA1(),
                )
                si["sid"] = asn1crypto.cms.SignerIdentifier(
                    {
                        "issuer_and_serial_number": asn1crypto.cms.IssuerAndSerialNumber(
                            {
                                "issuer": cert.issuer,
                                "serial_number": cert.serial_number,
                            }
                        ),
                    }
                )
                sd["signer_infos"] = [si]
                sig = asn1crypto.cms.ContentInfo()
                sig["content_type"] = "signed_data"
                sig["content"] = sd
                kwargs["HTTP_MDM_SIGNATURE"] = base64.b64encode(sig.dump())
        return method(url, **kwargs)

    def _put(
        self,
        url,
        payload,
        session=None,
        serial_number=None,
        att_serial_number=None,
        att_udid=None,
        sign_message=False,
        bad_signature=False,
    ):
        return self._call(
            self.client.put,
            url,
            payload,
            session,
            serial_number,
            att_serial_number,
            att_udid,
            sign_message,
            bad_signature,
        )

    def _get(self, url, session, sign_message=False):
        return self._call(
            self.client.get,
            url,
            payload=None,
            session=session,
            sign_message=sign_message,
        )

    def _assertAbort(self, post_event, reason, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MDMRequestEvent)
        self.assertEqual(last_event.payload["status"], "failure")
        self.assertEqual(last_event.payload["reason"], reason)
        for k, v in kwargs.items():
            if k == "serial_number":
                self.assertEqual(last_event.metadata.machine_serial_number, v)
            else:
                self.assertEqual(last_event.payload.get(k), v)

    def _assertSuccess(self, post_event, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MDMRequestEvent)
        self.assertEqual(last_event.payload["status"], "success")
        for k, v in kwargs.items():
            self.assertEqual(last_event.payload.get(k), v)

    def _assert_sync_tokens(self, actual, expected):
        iso_8601 = "%Y-%m-%dT%H:%M:%SZ"
        actual_datetime = datetime.strptime(actual["SyncTokens"]["Timestamp"], iso_8601)
        expected_datetime = datetime.strptime(expected["SyncTokens"]["Timestamp"], iso_8601)
        delta = abs((actual_datetime - expected_datetime).total_seconds())
        self.assertLessEqual(delta, 1.0)

        self.assertEqual(len(actual), 1)
        self.assertEqual(len(actual), len(expected))

        for key, value in actual["SyncTokens"].items():
            if (key != "Timestamp"):
                self.assertEqual(value, expected["SyncTokens"][key])

    def _add_blueprint(self, session):
        blueprint = Blueprint.objects.create(name=get_random_string(12))
        update_blueprint_serialized_artifacts(blueprint)
        session.enrolled_device.blueprint = blueprint
        session.enrolled_device.save()
        return blueprint

    def _force_profile(self, channel=Channel.DEVICE, name=None):
        if not name:
            name = get_random_string(12)
        artifact = Artifact.objects.create(
            name=name,
            type=Artifact.Type.PROFILE,
            channel=channel,
            platforms=[Platform.MACOS],
        )
        artifact_version = ArtifactVersion.objects.create(
            artifact=artifact, version=0, macos=True
        )
        payload_identifier = str(uuid.uuid4())
        return Profile.objects.create(
            artifact_version=artifact_version,
            filename=f"{name}.mobileconfig",
            source=plistlib.dumps(
                {
                    "PayloadContent": [],
                    "PayloadDisplayName": name,
                    "PayloadIdentifier": payload_identifier,
                    "PayloadRemovalDisallowed": False,
                    "PayloadType": "Configuration",
                    "PayloadUUID": str(uuid.uuid4()),
                    "PayloadVersion": 1,
                }
            ),
            payload_identifier=payload_identifier,
            payload_display_name=name,
            payload_description="",
        )

    def _force_blueprint_profile(self, session, channel=Channel.DEVICE):
        profile = self._force_profile(channel=channel)
        blueprint = self._add_blueprint(session)
        BlueprintArtifact.objects.get_or_create(
            artifact=profile.artifact_version.artifact,
            blueprint=blueprint,
            defaults={"macos": True},
        )
        update_blueprint_serialized_artifacts(blueprint)
        return profile

    # checkin - authenticate

    def test_unknown_message_type(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        response = self._put(
            reverse("mdm_public:checkin"),
            {"UDID": udid, "MessageType": "yolo"},
            session,
        )
        self.assertEqual(response.status_code, 400)
        self._assertAbort(
            post_event, "unknown message type", udid=udid, serial_number=serial_number
        )

    def test_unknown_topic(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        topic = get_random_string(12)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "unknown topic", topic=topic)

    def test_authenticate_dep_enrollment_session_macos(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        enrolled_device = session.enrolled_device
        self.assertEqual(enrolled_device.udid, udid)
        self.assertEqual(enrolled_device.serial_number, serial_number)
        self.assertEqual(enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertIsNone(enrolled_device.cert_att_serial_number)
        self.assertIsNone(enrolled_device.cert_att_udid)
        self.assertEqual(enrolled_device.platform, "macOS")
        self.assertTrue(enrolled_device.dep_enrollment)
        self.assertTrue(enrolled_device.user_enrollment is False)
        self.assertTrue(enrolled_device.user_approved_enrollment)
        self.assertTrue(enrolled_device.supervised)

    def test_authenticate_dep_enrollment_session_macos_with_cert_att(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "15.6.1",
            "BuildVersion": "21F79",
        }
        response = self._put(
            reverse("mdm_public:checkin"),
            payload,
            session,
            att_serial_number=serial_number,
            att_udid="att-udid",
        )
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        enrolled_device = session.enrolled_device
        self.assertEqual(enrolled_device.udid, udid)
        self.assertEqual(enrolled_device.serial_number, serial_number)
        self.assertEqual(enrolled_device.cert_not_valid_after, datetime(2034, 5, 6))
        self.assertEqual(enrolled_device.cert_att_serial_number, serial_number)
        self.assertEqual(enrolled_device.cert_att_udid, "att-udid")
        self.assertEqual(enrolled_device.platform, "macOS")
        self.assertTrue(enrolled_device.dep_enrollment)
        self.assertTrue(enrolled_device.user_enrollment is False)
        self.assertTrue(enrolled_device.user_approved_enrollment)
        self.assertTrue(enrolled_device.supervised)

    def test_authenticate_dep_enrollment_session_macos_mdm_signature_header(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(
            reverse("mdm_public:checkin"), payload, session, sign_message=True
        )
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(
            session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6)
        )
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertTrue(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised)

    def test_authenticate_dep_enrollment_session_macos_bad_mdm_signature_header(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(self.mbu)
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(
            reverse("mdm_public:checkin"),
            payload,
            session,
            sign_message=True,
            bad_signature=True,
        )
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "Invalid header signature")

    def test_authenticate_dep_enrollment_session_ios(self, post_event):
        enrollment_tag = Tag.objects.create(name=get_random_string(12))
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, realm_user=True, tags=[enrollment_tag]
        )
        self.assertEqual(session.status, DEPEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)

        # tags
        # add realm user to a group
        realm_group = RealmGroup.objects.create(
            realm=session.realm_user.realm, display_name=get_random_string(12)
        )
        RealmUserGroupMembership.objects.create(
            user=session.realm_user, group=realm_group
        )
        # unmanaged tag, must be kept
        unmanaged_tag = Tag.objects.create(name=get_random_string(12))
        MachineTag.objects.create(serial_number=serial_number, tag=unmanaged_tag)
        # managed tag to add
        tag_to_add = Tag.objects.create(name=get_random_string(12))
        RealmGroupTagMapping.objects.create(realm_group=realm_group, tag=tag_to_add)
        self.assertFalse(
            MachineTag.objects.filter(
                serial_number=serial_number, tag=tag_to_add
            ).exists()
        )
        # managed tag to remove
        tag_to_remove = Tag.objects.create(name=get_random_string(12))
        non_matching_realm_group = RealmGroup.objects.create(
            realm=session.realm_user.realm, display_name=get_random_string(12)
        )
        RealmGroupTagMapping.objects.create(
            realm_group=non_matching_realm_group, tag=tag_to_remove
        )
        MachineTag.objects.create(serial_number=serial_number, tag=tag_to_remove)

        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "iPhone13",
            "ModelName": "iPhone",
            "OSVersion": "16.2",
            "BuildVersion": "20C65",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(
            session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6)
        )
        self.assertEqual(session.enrolled_device.platform, "iOS")
        self.assertTrue(session.enrolled_device.dep_enrollment)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised)
        # tags
        self.assertTrue(
            MachineTag.objects.filter(
                serial_number=serial_number, tag=enrollment_tag
            ).exists()
        )
        self.assertTrue(
            MachineTag.objects.filter(
                serial_number=serial_number, tag=unmanaged_tag
            ).exists()
        )
        self.assertTrue(
            MachineTag.objects.filter(
                serial_number=serial_number, tag=tag_to_add
            ).exists()
        )
        self.assertFalse(
            MachineTag.objects.filter(
                serial_number=serial_number, tag=tag_to_remove
            ).exists()
        )

    def test_authenticate_ota_enrollment_session_macos(self, post_event):
        session, device_udid, serial_number = force_ota_enrollment_session(
            self.mbu, phase3=True
        )
        self.assertEqual(session.status, OTAEnrollmentSession.PHASE_3)
        self.assertIsNone(session.enrolled_device)
        payload = {
            "UDID": device_udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(
            reverse("mdm_public:checkin"), payload, session, serial_number=serial_number
        )
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, OTAEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, device_udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(
            session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6)
        )
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment is False)
        self.assertTrue(session.enrolled_device.user_enrollment is False)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertIsNone(session.enrolled_device.supervised)

    def test_authenticate_user_enrollment_session_macos(self, post_event):
        session, _, _ = force_user_enrollment_session(self.mbu)
        self.assertEqual(session.status, UserEnrollmentSession.STARTED)
        self.assertIsNone(session.enrolled_device)
        device_udid = get_random_string(12)
        serial_number = get_random_string(12)
        payload = {
            "UDID": device_udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(
            reverse("mdm_public:checkin"), payload, session, serial_number=serial_number
        )
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, new_enrolled_device=True, reenrollment=False)
        session.refresh_from_db()
        self.assertEqual(session.status, UserEnrollmentSession.AUTHENTICATED)
        self.assertEqual(session.enrolled_device.udid, device_udid)
        self.assertEqual(session.enrolled_device.serial_number, serial_number)
        self.assertEqual(
            session.enrolled_device.cert_not_valid_after, datetime(2034, 5, 6)
        )
        self.assertEqual(session.enrolled_device.platform, "macOS")
        self.assertTrue(session.enrolled_device.dep_enrollment is False)
        self.assertTrue(session.enrolled_device.user_enrollment)
        self.assertIsNone(session.enrolled_device.user_approved_enrollment)
        self.assertTrue(session.enrolled_device.supervised is False)

    def test_authenticate_new_enrollment_purged_state(self, post_event):
        # get a fully enrolled device
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        # simulate some state
        ed = session.enrolled_device
        self.assertIsNone(ed.last_ip)
        self.assertIsNone(ed.last_seen_at)
        self.assertIsNone(ed.last_notified_at)
        self.assertIsNone(ed.notification_queued_at)
        ed.last_ip = "127.0.0.1"
        ed.last_seen_at = datetime.utcnow()
        ed.last_notified_at = datetime.utcnow()
        ed.notification_queued_at = datetime.utcnow()
        ed.save()
        # new enrollment but not a re-enrollment session
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, device_udid=udid, serial_number=serial_number
        )
        payload = {
            "UDID": udid,
            "SerialNumber": serial_number,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "Authenticate",
            "Topic": session.get_enrollment().push_certificate.topic,
            "DeviceName": get_random_string(12),
            "Model": "Macmini9,1",
            "ModelName": "Mac mini",
            "OSVersion": "12.4",
            "BuildVersion": "21F79",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertSuccess(post_event, new_enrolled_device=False, reenrollment=False)
        self.assertEqual(response.status_code, 200)
        session.refresh_from_db()
        ed.refresh_from_db()
        self.assertEqual(session.enrolled_device, ed)
        self.assertIsNone(ed.last_ip)
        self.assertIsNone(ed.last_seen_at)
        self.assertIsNone(ed.last_notified_at)
        self.assertIsNone(ed.notification_queued_at)

    # checkin - user authenticate

    def test_device_channel_user_authenticate(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True
        )
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        payload = {
            "UDID": udid,
            "MessageType": "UserAutenticate",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 410)

    # checkin - token update

    def test_device_channel_token_update_no_awaiting_configuration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True
        )
        self.assertEqual(session.status, DEPEnrollmentSession.AUTHENTICATED)
        push_magic = get_random_string(12)
        token = get_random_string(12).encode("utf-8")
        unlock_token = get_random_string(12).encode("utf-8")
        payload = {
            "UDID": udid,
            # No UserID or EnrollmentUserID → Device Channel
            "MessageType": "TokenUpdate",
            "AwaitingConfiguration": False,
            "NotOnConsole": False,
            "PushMagic": push_magic,
            "Token": token,
            "Topic": session.get_enrollment().push_certificate.topic,
            "UnlockToken": unlock_token,
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(
            post_event,
            token_type="device",
            device_created=False,
            user_created=False,
            awaiting_configuration=False,
        )
        session.refresh_from_db()
        self.assertEqual(session.status, DEPEnrollmentSession.COMPLETED)
        self.assertEqual(session.enrolled_device.push_magic, push_magic)
        self.assertEqual(session.enrolled_device.token.tobytes(), token)
        self.assertEqual(session.enrolled_device.get_unlock_token(), unlock_token)
        self.assertIsNone(session.enrolled_device.bootstrap_token)

    def test_user_channel_token_update(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self.assertEqual(session.status, DEPEnrollmentSession.COMPLETED)
        user_id = str(uuid.uuid4())
        token = get_random_string(12).encode("utf-8")
        user_long_name = get_random_string(42)
        user_short_name = get_random_string(12)
        payload = {
            "UDID": udid,
            "UserID": user_id,  # → User channel
            "MessageType": "TokenUpdate",
            "AwaitingConfiguration": False,
            "NotOnConsole": False,
            "PushMagic": session.enrolled_device.push_magic,
            "Topic": session.get_enrollment().push_certificate.topic,
            "Token": token,
            "UserLongName": user_long_name,
            "UserShortName": user_short_name,
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(
            post_event, token_type="user", device_created=False, user_created=True
        )
        enrolled_user = session.enrolled_device.users.first()
        self.assertEqual(enrolled_user.user_id, user_id)
        self.assertEqual(enrolled_user.token.tobytes(), token)
        self.assertEqual(enrolled_user.long_name, user_long_name)
        self.assertEqual(enrolled_user.short_name, user_short_name)

    # checkin - set bootstrap token

    def test_set_bootstrap_token_no_awaiting_configuration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bootstrap_token = get_random_string(12).encode("utf-8")
        payload = {
            "UDID": udid,
            "MessageType": "SetBootstrapToken",
            "AwaitingConfiguration": False,
            "BootstrapToken": bootstrap_token,
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, awaiting_configuration=False)
        session.refresh_from_db()
        self.assertFalse(session.enrolled_device.awaiting_configuration)
        self.assertEqual(session.enrolled_device.get_bootstrap_token(), bootstrap_token)

    def test_set_bootstrap_token_awaiting_configuration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bootstrap_token = get_random_string(12).encode("utf-8")
        payload = {
            "UDID": udid,
            "MessageType": "SetBootstrapToken",
            "AwaitingConfiguration": True,
            "BootstrapToken": bootstrap_token,
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event, awaiting_configuration=True)
        session.refresh_from_db()
        self.assertTrue(session.enrolled_device.awaiting_configuration)
        self.assertEqual(session.enrolled_device.get_bootstrap_token(), bootstrap_token)

    # checkin - get bootstrap token

    def test_get_no_bootstrap_token_warning(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        payload = {
            "UDID": udid,
            "MessageType": "GetBootstrapToken",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, MDMRequestEvent)
        self.assertEqual(last_event.payload["status"], "warning")
        self.assertEqual(
            last_event.payload["reason"],
            f"Enrolled device {udid} has no bootstrap token",
        )
        data = plistlib.loads(response.content)
        self.assertEqual(data["BootstrapToken"], b"")

    def test_get_bootstrap_token(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bootstrap_token = get_random_string(12).encode("utf-8")
        session.enrolled_device.set_bootstrap_token(bootstrap_token)
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "GetBootstrapToken",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event)
        data = plistlib.loads(response.content)
        self.assertEqual(data["BootstrapToken"], bootstrap_token)

    # checkin - declarative management

    def test_declarative_management_no_blueprint_error(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration-items",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(
            post_event,
            "Missing blueprint. No declarative management possible.",
            data={"un": 2},
            endpoint="declaration-items",
        )

    def test_declarative_management_tokens(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "tokens",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        tokens_response, declarations_token = Target(
            session.enrolled_device
        ).sync_tokens
        self._assert_sync_tokens(json_response, tokens_response)
        self._assertSuccess(post_event, endpoint="tokens")
        session.enrolled_device.refresh_from_db()
        self.assertEqual(session.enrolled_device.declarations_token, declarations_token)

    @patch("zentral.contrib.mdm.apps_books.logger.error")
    def test_declarative_management_tokens_decl_no_default_loc_missing_assignment(self, logger_error, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.app.managed",
            decl_payload={"AppStoreID": "0123456789"},
        )
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "tokens",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        tokens_response, declarations_token = Target(
            session.enrolled_device
        ).sync_tokens
        self._assert_sync_tokens(json_response, tokens_response)
        self._assertSuccess(post_event, endpoint="tokens")
        session.enrolled_device.refresh_from_db()
        self.assertEqual(session.enrolled_device.declarations_token, declarations_token)
        logger_error.assert_called_once_with(
            "No location found for enrolled device %s, adamId %s",
            session.enrolled_device.serial_number,
            "0123456789",
        )

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_declarative_management_tokens_decl_default_loc_missing_assignment(self, location_cache_get, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.app.managed",
            decl_payload={"AppStoreID": "0123456789"},
        )
        blueprint.default_location = force_location()
        blueprint.save()
        client = Mock()
        event_id = str(uuid.uuid4())
        client.post_device_associations.return_value = event_id
        location_cache_get.return_value = blueprint.default_location, client
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "tokens",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        tokens_response, declarations_token = Target(
            session.enrolled_device
        ).sync_tokens
        self._assert_sync_tokens(json_response, tokens_response)
        self._assertSuccess(post_event, endpoint="tokens")
        session.enrolled_device.refresh_from_db()
        self.assertEqual(session.enrolled_device.declarations_token, declarations_token)
        location_cache_get.assert_called_once_with(str(blueprint.default_location.mdm_info_id))
        client.post_device_associations.asset_called_once_with(serial_number, [("0123456789", "STDQ")])
        # event marked as OTF assignment
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id)), "1")

    # declaration items

    def test_declarative_management_declaration_items(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration-items",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        self.assertEqual(
            json_response, Target(session.enrolled_device).declaration_items
        )

    @patch("zentral.contrib.mdm.apps_books.logger.exception")
    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_declarative_management_declaration_items_decl_missing_assignment_cli_err(
        self,
        location_cache_get,
        logger_exception,
        post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.app.managed",
            decl_payload={"AppStoreID": "0123456789"},
        )
        blueprint.default_location = force_location()
        blueprint.save()
        client = Mock()
        client.post_device_associations.side_effect = ValueError("Yolo")
        location_cache_get.return_value = blueprint.default_location, client
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration-items",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        self.assertEqual(
            json_response, Target(session.enrolled_device).declaration_items
        )
        client.post_device_associations.assert_called_once_with(
            serial_number, [("0123456789", "STDQ")]
        )
        logger_exception.assert_called_once_with("Could not post device %s associations", serial_number)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_declarative_management_declaration_items_decl_missing_assignment(
        self,
        location_cache_get,
        post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.app.managed",
            decl_payload={"AppStoreID": "0123456789"},
        )
        blueprint.default_location = force_location()
        blueprint.save()
        client = Mock()
        event_id = str(uuid.uuid4())
        client.post_device_associations.return_value = event_id
        location_cache_get.return_value = blueprint.default_location, client
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration-items",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        json_response = json.loads(response.content)
        self.assertEqual(
            json_response, Target(session.enrolled_device).declaration_items
        )
        client.post_device_associations.assert_called_once_with(
            serial_number, [("0123456789", "STDQ")]
        )
        # event marked as OTF assignment
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id)), "1")

    # status

    def test_declarative_management_status_report(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps(build_status_report()),
            "Endpoint": "status",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)

    # legacy profile

    def test_declarative_management_legacy_profile_declaration_device(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        profile = self._force_blueprint_profile(session)
        artifact_version = profile.artifact_version
        artifact = artifact_version.artifact
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.legacy-profile.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"].pop("ProfileURL")
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.legacy-profile.{artifact.pk}",
                "Payload": {},
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.configuration.legacy",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/profiles/")
        token = token.removesuffix("/")
        t_profile, t_session, t_user = load_legacy_profile_token(token)
        self.assertEqual(t_profile, profile)
        self.assertEqual(t_session, session)
        self.assertIsNone(t_user)

    def test_declarative_management_legacy_profile_declaration_device_retry(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        profile = self._force_blueprint_profile(session)
        artifact_version = profile.artifact_version
        artifact = artifact_version.artifact
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.legacy-profile.{artifact.pk}",
        }
        target = Target(session.enrolled_device)
        target.update_target_artifact(
            artifact_version, TargetArtifact.Status.FAILED
        )  # force retry
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"].pop("ProfileURL")
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.legacy-profile.{artifact.pk}",
                "Payload": {},
                "ServerToken": f"{artifact_version.pk}.rc-1",  # first retry
                "Type": "com.apple.configuration.legacy",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/profiles/")
        token = token.removesuffix("/")
        t_profile, t_session, t_user = load_legacy_profile_token(token)
        self.assertEqual(t_profile, profile)
        self.assertEqual(t_session, session)
        self.assertIsNone(t_user)

    def test_declarative_management_legacy_profile_declaration_user(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        profile = self._force_blueprint_profile(session, channel=Channel.USER)
        artifact_version = profile.artifact_version
        artifact = artifact_version.artifact
        payload = {
            "UDID": udid,
            "UserID": enrolled_user.user_id,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.legacy-profile.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"].pop("ProfileURL")
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.legacy-profile.{artifact.pk}",
                "Payload": {},
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.configuration.legacy",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/profiles/")
        token = token.removesuffix("/")
        t_profile, t_session, t_user = load_legacy_profile_token(token)
        self.assertEqual(t_profile, profile)
        self.assertEqual(t_session, session)
        self.assertEqual(t_user, enrolled_user)

    def test_declarative_management_legacy_profile_invalid_identifier(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/configuration/zentral.legacy-profile.",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Invalid Profile Identifier",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_legacy_profile_not_found(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        profile = self._force_profile()  # this profile is not in the blueprint
        self._force_blueprint_profile(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.legacy-profile.{profile.artifact_version.artifact.pk}",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            f"Could not find Profile artifact {profile.artifact_version.artifact.pk}",
            udid=udid,
            serial_number=serial_number,
        )

    # status subscriptions

    def test_declarative_no_client_capabilities_default_status_subscriptions_declaration(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self.assertIsNone(session.enrolled_device.client_capabilities)
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
                "Payload": {
                    "StatusItems": [
                        {"Name": "device.identifier.serial-number"},
                        {"Name": "device.identifier.udid"},
                        {"Name": "device.model.family"},
                        {"Name": "device.model.identifier"},
                        {"Name": "device.model.marketing-name"},
                        {"Name": "device.operating-system.build-version"},
                        {"Name": "device.operating-system.family"},
                        {"Name": "device.operating-system.marketing-name"},
                        {"Name": "device.operating-system.version"},
                        {"Name": "management.client-capabilities"},
                        {"Name": "management.declarations"},
                    ]
                },
                "ServerToken": "0ed215547af3061ce18ea6cf7a69dac4a3d52f3f",
                "Type": "com.apple.configuration.management.status-subscriptions",
            },
        )

    def test_declarative_no_client_items_default_status_subscriptions_declaration(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        session.enrolled_device.client_capabilities = {
            "supported-payloads": {}  # no status-items
        }
        session.enrolled_device.save()
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
                "Payload": {
                    "StatusItems": [
                        {"Name": "device.identifier.serial-number"},
                        {"Name": "device.identifier.udid"},
                        {"Name": "device.model.family"},
                        {"Name": "device.model.identifier"},
                        {"Name": "device.model.marketing-name"},
                        {"Name": "device.operating-system.build-version"},
                        {"Name": "device.operating-system.family"},
                        {"Name": "device.operating-system.marketing-name"},
                        {"Name": "device.operating-system.version"},
                        {"Name": "management.client-capabilities"},
                        {"Name": "management.declarations"},
                    ]
                },
                "ServerToken": "0ed215547af3061ce18ea6cf7a69dac4a3d52f3f",
                "Type": "com.apple.configuration.management.status-subscriptions",
            },
        )

    def test_declarative_management_status_subscriptions_declaration_device_channel(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        session.enrolled_device.client_capabilities = {
            "supported-payloads": {"status-items": ["yolo", "fomo", "test.yolo"]}
        }
        session.enrolled_device.save()
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
                "Payload": {"StatusItems": [{"Name": "fomo"}, {"Name": "yolo"}]},
                "ServerToken": "3b6c1269e23df247f53e2da7a7ebb127110ee2cc",
                "Type": "com.apple.configuration.management.status-subscriptions",
            },
        )

    def test_declarative_management_status_subscriptions_declaration_user_channel(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        enrolled_user.client_capabilities = {
            "supported-payloads": {"status-items": ["yolo", "fomo", "test.yolo"]}
        }
        enrolled_user.save()
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "UserID": enrolled_user.user_id,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions",
                "Payload": {"StatusItems": [{"Name": "fomo"}, {"Name": "yolo"}]},
                "ServerToken": "3b6c1269e23df247f53e2da7a7ebb127110ee2cc",
                "Type": "com.apple.configuration.management.status-subscriptions",
            },
        )

    # activation

    def test_declarative_management_activation_device_channel(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.activation",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        response_json.pop("ServerToken")  # always different
        self.assertEqual(
            response_json,
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.activation",
                "Payload": {
                    "StandardConfigurations": [
                        f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions"
                    ]
                },
                "Type": "com.apple.activation.simple",
            },
        )

    def test_declarative_management_activation_user_channel(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        blueprint = self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "UserID": enrolled_user.user_id,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}.activation",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        response_json = response.json()
        response_json.pop("ServerToken")  # always different
        self.assertEqual(
            response_json,
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.activation",
                "Payload": {
                    "StandardConfigurations": [
                        f"zentral.blueprint.{blueprint.pk}.management-status-subscriptions"
                    ]
                },
                "Type": "com.apple.activation.simple",
            },
        )

    # software update enforcement specific

    def test_declarative_management_softwareupdate_enforcement_specific_err(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.save()
        force_software_update(
            device_id=device_id, version="14.1.0", posting_date=date(2023, 10, 25)
        )
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            max_os_version="15",
            local_time=time(9, 30),
            delay_days=15,
        )
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "No software enforcement found for target",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_softwareupdate_enforcement_specific_latest_no_build(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.client_capabilities = MACOS_14_CLIENT_CAPABILITIES
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.save()
        force_software_update(
            device_id=device_id, version="14.1.0", posting_date=date(2023, 10, 25)
        )
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            max_os_version="15",
            local_time=time(9, 30),
            delay_days=15,
        )
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.softwareupdate-enforcement-specific",
                "Payload": {
                    "DetailsURL": "https://www.example.com",
                    "TargetOSVersion": "14.1",
                    "TargetLocalDateTime": "2023-11-09T09:30:00",
                },
                "ServerToken": "46e9bd884ed69f3596a19af1c3dd7debad77e998",
                "Type": "com.apple.configuration.softwareupdate.enforcement.specific",
            },
        )

    def test_declarative_management_softwareupdate_enforcement_specific_latest_build(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.client_capabilities = MACOS_14_CLIENT_CAPABILITIES
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.save()
        force_software_update(
            device_id=device_id,
            version="14.1.0",
            build="23B74",
            posting_date=date(2023, 10, 25),
        )
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            max_os_version="15",
            local_time=time(9, 30),
            delay_days=15,
        )
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.softwareupdate-enforcement-specific",
                "Payload": {
                    "DetailsURL": "https://www.example.com",
                    "TargetOSVersion": "14.1",
                    "TargetBuildVersion": "23B74",
                    "TargetLocalDateTime": "2023-11-09T09:30:00",
                },
                "ServerToken": "70f599a2446b04819b674530433c1f1322947ddb",
                "Type": "com.apple.configuration.softwareupdate.enforcement.specific",
            },
        )

    def test_declarative_management_softwareupdate_enforcement_specific_latest_same(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.client_capabilities = MACOS_14_CLIENT_CAPABILITIES
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.os_version = "14.1"
        session.enrolled_device.build_version = "23B74"
        session.enrolled_device.save()
        force_software_update(
            device_id=device_id, version="14.1.0", posting_date=date(2023, 10, 25)
        )
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            max_os_version="15",
            local_time=time(9, 30),
            delay_days=15,
        )
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.softwareupdate-enforcement-specific",
                "Payload": {
                    "DetailsURL": "https://www.example.com",
                    "TargetOSVersion": "14.1",
                    "TargetBuildVersion": "23B74",
                    "TargetLocalDateTime": "2023-11-09T09:30:00",
                },
                "ServerToken": "70f599a2446b04819b674530433c1f1322947ddb",
                "Type": "com.apple.configuration.softwareupdate.enforcement.specific",
            },
        )

    def test_declarative_management_softwareupdate_enforcement_specific_latest_not_found(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.client_capabilities = MACOS_14_CLIENT_CAPABILITIES
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.save()
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            max_os_version="15",
            local_time=time(9, 30),
            delay_days=15,
        )  # but no software update known for this device ID !!!
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(
            post_event,
            "No software update available for target",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_softwareupdate_enforcement_specific_one_time(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        device_id = get_random_string(8)
        session.enrolled_device.client_capabilities = MACOS_14_CLIENT_CAPABILITIES
        session.enrolled_device.device_information = {
            "SoftwareUpdateDeviceID": device_id
        }
        session.enrolled_device.save()
        sue = force_software_update_enforcement(
            details_url="https://www.example.com",
            os_version="14.1",
            build_version="23B74",
            local_datetime=datetime(2023, 10, 31, 9, 30),
        )
        blueprint = self._add_blueprint(session)
        blueprint.software_update_enforcements.add(sue)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.blueprint.{blueprint.pk}."
            "softwareupdate-enforcement-specific",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {
                "Identifier": f"zentral.blueprint.{blueprint.pk}.softwareupdate-enforcement-specific",
                "Payload": {
                    "DetailsURL": "https://www.example.com",
                    "TargetOSVersion": "14.1",
                    "TargetBuildVersion": "23B74",
                    "TargetLocalDateTime": "2023-10-31T09:30:00",
                },
                "ServerToken": "fe4df212271a9ca8f01cad718031d531c181cd78",
                "Type": "com.apple.configuration.softwareupdate.enforcement.specific",
            },
        )

    # cert asset

    def test_declarative_management_cert_asset_acme_if_possible(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.model = "Mac16,1"  # Silicon
        session.enrolled_device.os_version = "15.7.1"  # enough for ACME
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.cert-asset.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"]["Reference"].pop("DataURL")
        cert_asset = artifact_version.cert_asset
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.cert-asset.{artifact.pk}",
                "Payload": {
                    "Reference": {
                        "ContentType": "application/json",
                    },
                    "Accessible": cert_asset.accessible,
                },
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.asset.credential.acme",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/acme_credential/")
        token = token.removesuffix("/")
        t_cert_asset, t_session, t_user = load_cert_asset_token(token)
        self.assertEqual(t_cert_asset, cert_asset)
        self.assertEqual(t_session, session)
        self.assertIsNone(t_user)
        acme_issuer = cert_asset.acme_issuer
        response = self.client.get(url)
        self.assertEqual(
            response.json(),
            {
                "Attest": True,  # Silicon
                "ClientIdentifier": acme_issuer.get_backend_kwargs()["challenge"],
                "DirectoryURL": acme_issuer.directory_url,
                "HardwareBound": True,
                "KeySize": 384,
                "KeyType": "ECSECPrimeRandom",
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "dNSName": "yolo.example.com",
                    "rfc822Name": "yolo@example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "UsageFlags": 1,
            },
        )

    def test_declarative_management_cert_asset_scep_fallback(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.cert-asset.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"]["Reference"].pop("DataURL")
        cert_asset = artifact_version.cert_asset
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.cert-asset.{artifact.pk}",
                "Payload": {
                    "Reference": {
                        "ContentType": "application/json",
                    },
                    "Accessible": cert_asset.accessible,
                },
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.asset.credential.scep",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/scep_credential/")
        token = token.removesuffix("/")
        t_cert_asset, t_session, t_user = load_cert_asset_token(token)
        self.assertEqual(t_cert_asset, cert_asset)
        self.assertEqual(t_session, session)
        self.assertIsNone(t_user)
        response = self.client.get(url)
        scep_issuer = cert_asset.scep_issuer
        self.assertEqual(
            response.json(),
            {
                "Challenge": scep_issuer.get_backend_kwargs()["challenge"],
                "URL": scep_issuer.url,
                "Key Type": "RSA",
                "Key Usage": 0,
                "Keysize": 2048,
                "Name": scep_issuer.name,
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "dNSName": "yolo.example.com",
                    "rfc822Name": "yolo@example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
            },
        )

    def test_declarative_management_cert_asset_no_scep_fallback(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.cert-asset.{artifact.pk}",
        }
        cert_asset = artifact_version.cert_asset
        cert_asset.scep_issuer = None  # no fallback
        cert_asset.save()
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 400)

    def test_declarative_management_cert_asset_invalid_identifier(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.cert-asset.",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Invalid CertAsset Identifier",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_cert_asset_could_not_find(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.cert-asset.00000000-0000-0000-0000-000000000000",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Could not find CertAsset artifact 00000000-0000-0000-0000-000000000000",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_cert_asset_does_not_exist(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        artifact_version_pk = artifact_version.pk
        artifact_version.cert_asset.delete()  # create issue
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.cert-asset.{artifact.pk}",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            f"CertAsset for artifact version {artifact_version_pk} does not exist",
            udid=udid,
            serial_number=serial_number,
        )

    # data asset

    def test_declarative_management_data_asset(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.data-asset.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        url = declaration["Payload"]["Reference"].pop("DataURL")
        data_asset = artifact_version.data_asset
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.data-asset.{artifact.pk}",
                "Payload": {
                    "Reference": {
                        "ContentType": "application/zip",
                        "Size": data_asset.file_size,
                        "Hash-SHA-256": data_asset.file_sha256,
                    }
                },
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.asset.data",
            },
        )
        token = url.removeprefix("https://zentral/public/mdm/data_assets/")
        token = token.removesuffix("/")
        t_data_asset, t_session, t_user = load_data_asset_token(token)
        self.assertEqual(t_data_asset, data_asset)
        self.assertEqual(t_session, session)
        self.assertIsNone(t_user)

    def test_declarative_management_data_asset_invalid_identifier(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.data-asset.",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Invalid DataAsset Identifier",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_data_asset_could_not_find(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.data-asset.00000000-0000-0000-0000-000000000000",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Could not find DataAsset artifact 00000000-0000-0000-0000-000000000000",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_data_asset_does_not_exist(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        artifact_version_pk = artifact_version.pk
        artifact_version.data_asset.delete()  # create issue
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/asset/zentral.data-asset.{artifact.pk}",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            f"DataAsset for artifact version {artifact_version_pk} does not exist",
            udid=udid,
            serial_number=serial_number,
        )

    # declaration

    def test_declarative_management_declaration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        # add a DataAsset not directly included in the blueprint
        data_asset_artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        # add a Declaration that references the DataAsset and is included in the blueprint
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.services.configuration-files",
            decl_payload={
                "YOLO": "$ENROLLED_DEVICE.SERIAL_NUMBER",  # just for this test!
                "ServiceType": "com.apple.sudo",
                "DataAssetReference": f"ztl:{data_asset_artifact.pk}",
            },
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.declaration.{artifact.pk}",
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        declaration = json.loads(response.content)
        self.assertEqual(
            declaration,
            {
                "Identifier": f"zentral.declaration.{artifact.pk}",
                "Payload": {
                    "YOLO": serial_number,  # variable substitution
                    "ServiceType": "com.apple.sudo",
                    "DataAssetReference": f"zentral.data-asset.{data_asset_artifact.pk}",  # ref substitution
                },
                "ServerToken": str(artifact_version.pk),
                "Type": "com.apple.configuration.services.configuration-files",
            },
        )

    def test_declarative_management_declaration_invalid_identifier(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.declaration.",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Invalid Declaration Identifier",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_declaration_could_not_find(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.declaration.00000000-0000-0000-0000-000000000000",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Could not find Declaration artifact 00000000-0000-0000-0000-000000000000",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_declaration_does_not_exist(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        artifact_version_pk = artifact_version.pk
        artifact_version.declaration.delete()  # create issue
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.declaration.{artifact.pk}",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            f"Declaration for artifact version {artifact_version_pk} does not exist",
            udid=udid,
            serial_number=serial_number,
        )

    def test_declarative_management_declaration_unknown_type(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        # add a DataAsset not directly included in the blueprint
        data_asset_artifact, _ = force_artifact(artifact_type=Artifact.Type.DATA_ASSET)
        # add a Declaration that references the DataAsset and is included in the blueprint
        bpa, artifact, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CONFIGURATION,
            decl_type="com.apple.configuration.services.configuration-files",
            decl_payload={
                "YOLO": "$ENROLLED_DEVICE.SERIAL_NUMBER",  # just for this test!
                "ServiceType": "com.apple.sudo",
                "DataAssetReference": f"ztl:{data_asset_artifact.pk}",
            },
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        # create the issue
        artifact_version.declaration.type = "com.apple.does_not_exist"
        artifact_version.declaration.save()
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": f"declaration/configuration/zentral.declaration.{artifact.pk}",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event,
            "Unknown declaration type com.apple.does_not_exist",
            udid=udid,
            serial_number=serial_number,
        )

    # unknown declaration

    def test_declarative_management_unknown_declaration(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        self._add_blueprint(session)
        payload = {
            "UDID": udid,
            "MessageType": "DeclarativeManagement",
            "Data": json.dumps({"un": 2}),
            "Endpoint": "declaration/asset/zentral.yolo.fomo",
        }
        self._put(reverse("mdm_public:checkin"), payload, session)
        self._assertAbort(
            post_event, "Unknown declaration", udid=udid, serial_number=serial_number
        )

    # checking - checkout

    def test_checkout(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_device = session.enrolled_device
        self.assertIsNone(enrolled_device.checkout_at)
        payload = {
            "UDID": udid,
            "MessageType": "CheckOut",
            "Topic": session.get_enrollment().push_certificate.topic,
        }
        response = self._put(reverse("mdm_public:checkin"), payload, session)
        self.assertEqual(response.status_code, 200)
        self._assertSuccess(post_event)
        enrolled_device.refresh_from_db()
        self.assertIsNone(enrolled_device.token)
        self.assertIsNone(enrolled_device.push_magic)
        self.assertIsNone(enrolled_device.get_bootstrap_token())
        self.assertIsNone(enrolled_device.get_unlock_token())
        self.assertIsNotNone(enrolled_device.checkout_at)

    # connect

    def test_device_channel_connect_missing_status(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        payload = {}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "missing request status")

    def test_device_channel_connect_unknown_status(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        payload = {"Status": "yolo"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 400)
        self._assertAbort(post_event, "unknown request status")

    def test_device_channel_connect_idle_base_inventory_up_to_date_no_command(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        now = datetime.utcnow()
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.device_information_updated_at = now
        enrolled_device.security_info_updated_at = now
        enrolled_device.save()
        self.assertIsNone(enrolled_device.last_ip)
        self.assertIsNone(enrolled_device.last_seen_at)
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.last_ip, "127.0.0.1")
        self.assertTrue(enrolled_device.last_seen_at > now)

    def test_device_channel_connect_idle_base_inventory_not_up_to_date_command(
        self, post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        now = datetime.utcnow()
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        self.assertIsNone(enrolled_device.device_information_updated_at)
        self.assertIsNone(enrolled_device.security_info_updated_at)
        self.assertIsNone(enrolled_device.last_ip)
        self.assertIsNone(enrolled_device.last_seen_at)
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 200)
        data = plistlib.loads(response.content)
        self.assertEqual(data["Command"]["RequestType"], "DeviceInformation")
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.last_ip, "127.0.0.1")
        self.assertTrue(enrolled_device.last_seen_at > now)

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_device_channel_connect_idle_store_app_missing_assignment(
        self,
        location_cache_get,
        post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        _, _, (av,) = force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.STORE_APP,
        )
        now = datetime.utcnow()
        # inventory up to date
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.device_information_updated_at = now
        enrolled_device.security_info_updated_at = now
        enrolled_device.save()
        client = Mock()
        event_id = str(uuid.uuid4())
        client.post_device_associations.return_value = event_id
        location_cache_get.return_value = av.store_app.location_asset.location, client
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        # no available assignment → no command
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        # no available assignment → association request
        client.post_device_associations.assert_called_once_with(
            serial_number, [(av.store_app.location_asset.asset.adam_id,
                             av.store_app.location_asset.asset.pricing_param)]
        )
        # association event set in cache to be recognized as OTF assignment when processing the notifications
        self.assertEqual(cache.get(get_otf_association_cache_key(event_id)), "1")

    @patch("zentral.contrib.mdm.apps_books.location_cache.get")
    def test_device_channel_connect_idle_store_app_existing_assignment(
        self,
        location_cache_get,
        post_event
    ):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        blueprint = self._add_blueprint(session)
        _, _, (av,) = force_blueprint_artifact(
            blueprint=blueprint,
            artifact_type=Artifact.Type.STORE_APP,
        )
        location_asset = av.store_app.location_asset
        now = datetime.utcnow()
        # inventory up to date
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.device_information_updated_at = now
        enrolled_device.security_info_updated_at = now
        enrolled_device.save()
        client = Mock()
        location_cache_get.return_value = av.store_app.location_asset.location, client
        # existing assignment
        DeviceAssignment.objects.create(
            location_asset=location_asset,
            serial_number=serial_number,
        )
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        # existing assignment → install app command
        data = plistlib.loads(response.content)
        self.assertEqual(data["Command"]["RequestType"], "InstallApplication")
        self.assertEqual(data["Command"]["iTunesStoreID"], int(location_asset.asset.adam_id))
        # existing assignment → no association request
        client.post_device_associations.assert_not_called()

    def test_user_channel_connect_idle_no_command(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        self.assertIsNone(enrolled_user.last_ip)
        self.assertIsNone(enrolled_user.last_seen_at)
        now = datetime.utcnow()
        payload = {"UDID": udid, "Status": "Idle", "UserID": enrolled_user.user_id}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        enrolled_user.refresh_from_db()
        self.assertEqual(enrolled_user.last_ip, "127.0.0.1")
        self.assertTrue(enrolled_user.last_seen_at > now)

    def test_device_channel_connect_idle_device_cert_expiry_reenroll(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        session.enrolled_device.cert_not_valid_after = datetime.utcnow() + timedelta(
            days=1
        )
        now = datetime.utcnow()
        session.enrolled_device.device_information_updated_at = now
        session.enrolled_device.security_info_updated_at = now
        session.enrolled_device.save()
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 200)
        data = plistlib.loads(response.content)
        self.assertEqual(data["Command"]["RequestType"], "InstallProfile")
        command_uuid = data["CommandUUID"]
        db_command = DeviceCommand.objects.get(uuid=command_uuid)
        self.assertEqual(db_command.name, "Reenroll")
        self.assertEqual(db_command.enrolled_device, session.enrolled_device)
        certificates, profile_data = verify_signed_payload(data["Command"]["Payload"])
        profile = plistlib.loads(profile_data)
        mdm_payload = scep_payload = None
        for payload in profile["PayloadContent"]:
            payload_type = payload["PayloadType"]
            if payload_type == "com.apple.security.scep":
                scep_payload = payload
            elif payload_type == "com.apple.mdm":
                mdm_payload = payload
        resession = (
            ReEnrollmentSession.objects.filter(enrolled_device__udid=udid)
            .order_by("-pk")
            .first()
        )
        self.assertEqual(
            mdm_payload["IdentityCertificateUUID"], scep_payload["PayloadUUID"]
        )
        self.assertEqual(
            scep_payload["PayloadContent"]["Subject"][0][0],
            ["CN", f"MDM$RE${resession.enrollment_secret.secret}"],
        )

    def test_device_channel_connect_command_acknowledged(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        now = datetime.utcnow()
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.device_information_updated_at = now
        enrolled_device.security_info_updated_at = now
        enrolled_device.save()
        cmd_payload = {
            "RequestType": "InstalledApplicationList",
            "ManagedAppsOnly": False,
        }
        cmd = CustomCommand.create_for_device(
            enrolled_device,
            kwargs={"command": plistlib.dumps(cmd_payload).decode("utf-8")},
        )
        self.assertIsNone(enrolled_device.last_ip)
        self.assertIsNone(enrolled_device.last_seen_at)
        payload = {
            "UDID": udid,
            "Status": "Acknowledged",
            "CommandUUID": str(cmd.uuid).upper(),
            "InstalledApplicationList": [],
        }
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.content, b"")
        self.assertEqual(response.status_code, 200)
        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.last_ip, "127.0.0.1")
        self.assertTrue(enrolled_device.last_seen_at > now)
        cmd.db_command.refresh_from_db()
        self.assertEqual(cmd.db_command.status, Command.Status.ACKNOWLEDGED)

    def test_device_channel_connect_blocked(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.blocked_at = datetime.utcnow()
        enrolled_device.save()
        payload = {"UDID": udid, "Status": "Idle"}
        response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 401)

    def test_process_set_device_lock_and_clear(self, post_event):
        session, udid, serial_number = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_device = EnrolledDevice.objects.get(udid=udid)
        enrolled_device.platform = Platform.MACOS

        form = DeviceLock.form_class(
            {}, channel=Channel.DEVICE, enrolled_device=enrolled_device
        )

        uuid = uuid4()
        cmd = DeviceLock.create_for_device(
            enrolled_device,
            kwargs=form.get_command_kwargs_with_data(uuid, {"pin": "123456"}),
            uuid=uuid,
        )
        response_ack = self._put(
            reverse("mdm_public:connect"),
            payload={
                "UDID": enrolled_device.udid,
                "Status": "Acknowledged",
                "CommandUUID": str(cmd.uuid).upper(),
            },
            session=session,
        )

        self.assertEqual(response_ack.status_code, 200)
        cmd.db_command.refresh_from_db()
        cmd = load_command(cmd.db_command)
        self.assertEqual(cmd.status, Command.Status.ACKNOWLEDGED)

        enrolled_device.refresh_from_db()
        self.assertEqual(enrolled_device.get_device_lock_pin(), "123456")

        # reset devise lock pin by calling the connect endpoint
        payload = {"UDID": udid, "Status": "Idle"}
        with self.captureOnCommitCallbacks(execute=True):
            response = self._put(reverse("mdm_public:connect"), payload, session)
        self.assertEqual(response.status_code, 200)
        enrolled_device.refresh_from_db()
        self.assertIsNone(enrolled_device.get_device_lock_pin())
        self.assertIsNone(enrolled_device.device_lock_pin_updated_at)

        # event
        events = list(call_args.args[0] for call_args in post_event.call_args_list)
        self.assertEqual(len(events), 3)
        event = events[2]
        self.assertIsInstance(event, DeviceLockPinClearedEvent)
        self.assertEqual(event.payload, {})
        metadata = event.metadata.serialize()
        self.assertEqual(
            metadata["machine_serial_number"], enrolled_device.serial_number
        )
        self.assertEqual(set(metadata["tags"]), {"mdm", "device_lock_pin"})

    # acme credential download view

    def test_acme_credential_bad_token(self, post_event):
        response = self.client.get(
            reverse("mdm_public:acme_credential", args=("bad_token",))
        )
        self.assertEqual(response.status_code, 400)

    def test_acme_credential_404(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), uuid.uuid4()
        )
        response = self.client.get(reverse("mdm_public:acme_credential", args=(token,)))
        self.assertEqual(response.status_code, 404)

    def test_acme_credential_no_acme_issuer_400(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        artifact_version.cert_asset.acme_issuer = None  # No ACME issuer → 400
        artifact_version.cert_asset.save()

        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:acme_credential", args=(token,)))
        self.assertEqual(response.status_code, 400)

    def test_acme_credential_device_not_compatible_400(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:acme_credential", args=(token,)))
        self.assertEqual(response.status_code, 400)

    def test_acme_credential_device(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.model = "Mac16,1"  # Silicon
        session.enrolled_device.os_version = "15.7.1"  # enough for ACME
        session.enrolled_device.save()
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:acme_credential", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        acme_issuer = artifact_version.cert_asset.acme_issuer
        self.assertEqual(
            response.json(),
            {
                "Attest": True,
                "ClientIdentifier": acme_issuer.get_backend_kwargs()["challenge"],
                "DirectoryURL": acme_issuer.directory_url,
                "HardwareBound": True,
                "KeySize": 384,
                "KeyType": "ECSECPrimeRandom",
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "dNSName": "yolo.example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "rfc822Name": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "UsageFlags": 1,
            },
        )

    def test_acme_credential_user(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET, channel=Channel.USER
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.model = "MacBookPro16,4"  # T2
        session.enrolled_device.os_version = "15.6.1"  # enough for ACME
        session.enrolled_device.save()
        enrolled_user = force_enrolled_user(session.enrolled_device)
        cert_asset = artifact_version.cert_asset
        cert_asset.subject_alt_name = {
            "uniformResourceIdentifier": "https://example.com/$ENROLLED_DEVICE.SERIAL_NUMBER",
            "ntPrincipalName": "$ENROLLED_USER.SHORT_NAME",
        }
        cert_asset.save()
        acme_issuer = cert_asset.acme_issuer
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device, enrolled_user), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:acme_credential", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        self.assertEqual(
            response.json(),
            {
                "Attest": False,  # not Silicon
                "ClientIdentifier": acme_issuer.get_backend_kwargs()["challenge"],
                "DirectoryURL": acme_issuer.directory_url,
                "HardwareBound": True,
                "KeySize": 384,
                "KeyType": "ECSECPrimeRandom",
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "ntPrincipalName": enrolled_user.short_name,
                    "uniformResourceIdentifier": f"https://example.com/{session.enrolled_device.serial_number}",
                },
                "UsageFlags": 1,
            },
        )

    # scep credential download view

    def test_scep_credential_bad_token(self, post_event):
        response = self.client.get(
            reverse("mdm_public:scep_credential", args=("bad_token",))
        )
        self.assertEqual(response.status_code, 400)

    def test_scep_credential_404(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), uuid.uuid4()
        )
        response = self.client.get(reverse("mdm_public:scep_credential", args=(token,)))
        self.assertEqual(response.status_code, 404)

    def test_acme_credential_no_scep_issuer_400(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        artifact_version.cert_asset.scep_issuer = None  # No ACME issuer → 400
        artifact_version.cert_asset.save()

        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:scep_credential", args=(token,)))
        self.assertEqual(response.status_code, 400)

    def test_scep_credential_device(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:scep_credential", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        scep_issuer = artifact_version.cert_asset.scep_issuer
        self.assertEqual(
            response.json(),
            {
                "Challenge": scep_issuer.get_backend_kwargs()["challenge"],
                "Key Type": "RSA",
                "Key Usage": 0,
                "Keysize": 2048,
                "Name": scep_issuer.name,
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "dNSName": "yolo.example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "rfc822Name": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "URL": scep_issuer.url,
            },
        )

    def test_scep_credential_user(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.CERT_ASSET, channel=Channel.USER
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        enrolled_user = force_enrolled_user(session.enrolled_device)
        token = dump_cert_asset_token(
            session, Target(session.enrolled_device, enrolled_user), artifact_version.pk
        )
        response = self.client.get(reverse("mdm_public:scep_credential", args=(token,)))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/json")
        scep_issuer = artifact_version.cert_asset.scep_issuer
        self.assertEqual(
            response.json(),
            {
                "Challenge": scep_issuer.get_backend_kwargs()["challenge"],
                "Key Type": "RSA",
                "Key Usage": 0,
                "Keysize": 2048,
                "Name": scep_issuer.name,
                "Subject": [[["CN", "YOLO"]]],
                "SubjectAltName": {
                    "dNSName": "yolo.example.com",
                    "ntPrincipalName": "yolo@example.com",
                    "rfc822Name": "yolo@example.com",
                    "uniformResourceIdentifier": "https://example.com/yolo",
                },
                "URL": scep_issuer.url,
            },
        )

    # data asset download view

    def test_data_asset_download_bad_token(self, post_event):
        response = self.client.get(
            reverse("mdm_public:data_asset_download_view", args=("bad_token",))
        )
        self.assertEqual(response.status_code, 400)

    def test_data_asset_download_404(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        token = dump_data_asset_token(
            session, Target(session.enrolled_device), uuid.uuid4()
        )
        response = self.client.get(
            reverse("mdm_public:data_asset_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 404)

    def test_data_asset_download_view_device(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_data_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(
            reverse("mdm_public:data_asset_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/zip")
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(response.getvalue())))

    @patch("zentral.contrib.mdm.public_views.mdm.file_storage_has_signed_urls")
    def test_data_asset_download_view_device_redirect(
        self, file_storage_has_signed_urls, post_event
    ):
        file_storage_has_signed_urls.return_value = True
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        token = dump_data_asset_token(
            session, Target(session.enrolled_device), artifact_version.pk
        )
        response = self.client.get(
            reverse("mdm_public:data_asset_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 302)

    def test_data_asset_download_view_user(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        bpa, _, (artifact_version,) = force_blueprint_artifact(
            artifact_type=Artifact.Type.DATA_ASSET, channel=Channel.USER
        )
        session.enrolled_device.blueprint = bpa.blueprint
        session.enrolled_device.save()
        enrolled_user = force_enrolled_user(session.enrolled_device)
        token = dump_data_asset_token(
            session, Target(session.enrolled_device, enrolled_user), artifact_version.pk
        )
        response = self.client.get(
            reverse("mdm_public:data_asset_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["Content-Type"], "application/zip")
        self.assertTrue(zipfile.is_zipfile(io.BytesIO(response.getvalue())))

    # profile download view

    def test_profile_download_bad_token(self, post_event):
        response = self.client.get(
            reverse("mdm_public:profile_download_view", args=("bad_token",))
        )
        self.assertEqual(response.status_code, 400)

    def test_profile_download_404(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        token = dump_legacy_profile_token(
            session, Target(session.enrolled_device), uuid.uuid4()
        )
        response = self.client.get(
            reverse("mdm_public:profile_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 404)

    def test_profile_download_view_device(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        profile = self._force_profile(name="Test $ENROLLED_DEVICE.SERIAL_NUMBER")
        token = dump_legacy_profile_token(
            session, Target(session.enrolled_device), profile.artifact_version.pk
        )
        response = self.client.get(
            reverse("mdm_public:profile_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Content-Type"], "application/x-apple-aspen-config"
        )
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(
            payload["PayloadDisplayName"],
            f"Test {session.enrolled_device.serial_number}",
        )

    def test_profile_download_view_user(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        enrolled_user = force_enrolled_user(session.enrolled_device)
        profile = self._force_profile(name="Test $ENROLLED_USER.SHORT_NAME")
        token = dump_legacy_profile_token(
            session,
            Target(session.enrolled_device, enrolled_user),
            profile.artifact_version.pk,
        )
        response = self.client.get(
            reverse("mdm_public:profile_download_view", args=(token,))
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.headers["Content-Type"], "application/x-apple-aspen-config"
        )
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(
            payload["PayloadDisplayName"], f"Test {enrolled_user.short_name}"
        )

    # enterprise download view

    def test_enterprise_app_download_404(self, post_event):
        response = self.client.get(
            reverse("mdm_public:enterprise_app_download", args=(uuid.uuid4(),))
        )
        self.assertEqual(response.status_code, 404)

    def test_enterprise_app_download(self, post_event):
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        cmd = InstallEnterpriseApplication.create_for_device(
            session.enrolled_device, artifact_version
        )
        response = self.client.get(
            reverse("mdm_public:enterprise_app_download", args=(cmd.uuid,))
        )
        self.assertEqual(response.status_code, 200)

    @patch("zentral.contrib.mdm.public_views.mdm.file_storage_has_signed_urls")
    def test_enterprise_app_download_redirect(
        self, file_storage_has_signed_urls, post_event
    ):
        file_storage_has_signed_urls.return_value = True
        session, _, _ = force_dep_enrollment_session(
            self.mbu, authenticated=True, completed=True
        )
        artifact, (artifact_version,) = force_artifact(
            artifact_type=Artifact.Type.ENTERPRISE_APP
        )
        cmd = InstallEnterpriseApplication.create_for_device(
            session.enrolled_device, artifact_version
        )
        response = self.client.get(
            reverse("mdm_public:enterprise_app_download", args=(cmd.uuid,))
        )
        self.assertEqual(response.status_code, 302)
