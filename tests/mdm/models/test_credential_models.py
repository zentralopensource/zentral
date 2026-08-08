import hashlib
import json
from datetime import timedelta
from django.test import TestCase
from django.utils.crypto import get_random_string
from tests.mdm.utils import force_dep_virtual_server, force_push_certificate
from tests.zentral_test_utils.assertions.serialization_assertions import SerializeForEventAssertions
from zentral.contrib.mdm.crypto import certificate_sha256_fingerprint
from zentral.contrib.mdm.models import PushCertificate
from zentral.utils.time import naive_utcnow


class TestMDMCredentialModelSerialization(TestCase, SerializeForEventAssertions):
    """The push certificate and the DEP token are the MDM's credentials. Their audit events
    carry enough to tell one certificate from another, and none of the key material."""

    maxDiff = None

    # fingerprint helper

    def test_certificate_sha256_fingerprint(self):
        self.assertEqual(
            certificate_sha256_fingerprint(b"yolo"),
            hashlib.sha256(b"yolo").hexdigest(),
        )

    def test_certificate_sha256_fingerprint_accepts_a_memoryview(self):
        # a BinaryField read back from the database is not always bytes
        self.assertEqual(
            certificate_sha256_fingerprint(memoryview(b"yolo")),
            hashlib.sha256(b"yolo").hexdigest(),
        )

    def test_certificate_sha256_fingerprint_without_certificate(self):
        for empty in (None, b"", ""):
            with self.subTest(empty=empty):
                self.assertIsNone(certificate_sha256_fingerprint(empty))

    # push certificate

    def test_push_certificate_serialize_for_event_keys_only(self):
        push_certificate = force_push_certificate()
        self.assertEqual(
            push_certificate.serialize_for_event(keys_only=True),
            {"pk": push_certificate.pk, "name": push_certificate.name},
        )

    def test_push_certificate_serialize_for_event(self):
        push_certificate = force_push_certificate(with_material=True)
        d = push_certificate.serialize_for_event()
        self.assertEqual(
            set(d),
            {"pk", "name", "provisioning_uid", "topic", "not_before", "not_after",
             "certificate_sha256", "created_at", "updated_at"},
        )
        self.assertEqual(d["topic"], push_certificate.topic)
        self.assertEqual(d["certificate_sha256"],
                         hashlib.sha256(bytes(push_certificate.certificate)).hexdigest())
        self.assert_serialize_for_event_is_json_native(push_certificate)

    def test_push_certificate_serialize_for_event_has_no_private_key(self):
        push_certificate = force_push_certificate(with_material=True)
        self.assertTrue(push_certificate.private_key)
        serialized = json.dumps(push_certificate.serialize_for_event())
        self.assertNotIn("private_key", serialized)
        # neither the ciphertext nor the key itself
        self.assertNotIn(push_certificate.private_key, serialized)
        self.assertNotIn(push_certificate.get_private_key().decode("utf-8"), serialized)

    def test_push_certificate_serialize_for_event_before_the_certificate_is_uploaded(self):
        # CreatePushCertificateView makes one with only a name, and the certificate is uploaded
        # later, so every field it reports has to survive being null
        push_certificate = PushCertificate.objects.create(name=get_random_string(12))
        d = push_certificate.serialize_for_event()
        self.assertIsNone(d["certificate_sha256"])
        self.assertIsNone(d["not_before"])
        self.assertIsNone(d["not_after"])
        self.assertIsNone(d["topic"])
        self.assert_serialize_for_event_is_json_native(push_certificate)

    # DEP token

    def test_dep_token_serialize_for_event(self):
        dep_token = force_dep_virtual_server().token
        d = dep_token.serialize_for_event()
        self.assertEqual(
            set(d),
            {"pk", "certificate_sha256", "access_token_expiry", "last_synced_at", "created_at", "updated_at"},
        )
        self.assert_serialize_for_event_is_json_native(dep_token)

    def test_dep_token_serialize_for_event_has_no_point_in_time_expiry_flags(self):
        # a stored event must not carry a value that was only true when it was serialized
        dep_token = force_dep_virtual_server().token
        dep_token.access_token_expiry = naive_utcnow() - timedelta(days=1)
        dep_token.save()
        self.assertTrue(dep_token.has_expired())
        self.assertTrue(dep_token.expires_soon())
        d = dep_token.serialize_for_event()
        self.assertNotIn("has_expired", d)
        self.assertNotIn("expires_soon", d)
        self.assertEqual(d["access_token_expiry"], dep_token.access_token_expiry.isoformat())

    def test_dep_token_serialize_for_event_keys_only(self):
        dep_token = force_dep_virtual_server().token
        self.assertEqual(dep_token.serialize_for_event(keys_only=True), {"pk": dep_token.pk})

    def test_dep_token_serialize_for_event_has_no_secrets(self):
        dep_token = force_dep_virtual_server().token
        dep_token.set_private_key(b"PRIVATE-KEY-MATERIAL")
        dep_token.set_consumer_secret("CONSUMER-SECRET-MATERIAL")
        dep_token.set_access_secret("ACCESS-SECRET-MATERIAL")
        dep_token.consumer_key = "CONSUMER-KEY"
        dep_token.access_token = "ACCESS-TOKEN"
        dep_token.sync_cursor = "SYNC-CURSOR"
        dep_token.save()
        serialized = json.dumps(dep_token.serialize_for_event())
        for absent in ("PRIVATE-KEY-MATERIAL", "CONSUMER-SECRET-MATERIAL", "ACCESS-SECRET-MATERIAL",
                       dep_token.private_key, dep_token.consumer_secret, dep_token.access_secret,
                       "CONSUMER-KEY", "ACCESS-TOKEN", "SYNC-CURSOR"):
            with self.subTest(absent=absent[:24]):
                self.assertNotIn(absent, serialized)

    # DEP virtual server, whose only editable field is the default enrollment

    def test_dep_virtual_server_serialize_for_event(self):
        virtual_server = force_dep_virtual_server()
        d = virtual_server.serialize_for_event()
        self.assertEqual(
            set(d),
            {"pk", "uuid", "name", "default_enrollment", "token", "created_at", "updated_at"},
        )
        self.assertIsNone(d["default_enrollment"])
        self.assertEqual(d["token"], {"pk": virtual_server.token.pk})
        self.assert_serialize_for_event_is_json_native(virtual_server)

    def test_dep_virtual_server_serialize_for_event_keys_only(self):
        virtual_server = force_dep_virtual_server()
        self.assertEqual(
            virtual_server.serialize_for_event(keys_only=True),
            {"pk": virtual_server.pk, "uuid": str(virtual_server.uuid), "name": virtual_server.name},
        )

    def test_dep_virtual_server_serialize_for_event_has_no_token_secrets(self):
        virtual_server = force_dep_virtual_server()
        virtual_server.token.set_access_secret(get_random_string(12))
        virtual_server.token.save()
        serialized = json.dumps(virtual_server.serialize_for_event())
        self.assertNotIn(virtual_server.token.access_secret, serialized)
