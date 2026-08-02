import hashlib
import json
from unittest.mock import patch

from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.models import PushCertificate
from zentral.core.events.base import AuditEvent

from .utils import force_dep_enrollment, force_push_certificate, force_push_certificate_material


class CredentialAuditEventTestCase(TestCase, LoginCase):
    """The push certificate and the DEP token are what let Zentral manage and enroll devices,
    so replacing or deleting one has to leave a trail — without the key material."""

    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "mdm"

    def get_audit_event(self, post_event):
        events = [c.args[0] for c in post_event.call_args_list if isinstance(c.args[0], AuditEvent)]
        self.assertEqual(len(events), 1)
        return events[0]

    # push certificates

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_push_certificate_audit_event(self, post_event):
        self.login("mdm.add_pushcertificate", "mdm.view_pushcertificate")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("mdm:create_push_certificate"), {"name": name}, follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "created")
        self.assertEqual(event.payload["object"]["model"], "mdm.pushcertificate")
        self.assertEqual(event.payload["object"]["pk"], str(PushCertificate.objects.get(name=name).pk))
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["name"], name)
        # created before any material is uploaded
        self.assertIsNone(new_value["certificate_sha256"])
        self.assertIsNone(new_value["topic"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_push_certificate_audit_event(self, post_event):
        self.login("mdm.add_pushcertificate", "mdm.view_pushcertificate")
        name = get_random_string(12)
        cert_pem, privkey_pem, privkey_password = force_push_certificate_material()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("mdm:upload_push_certificate"),
                                        {"name": name,
                                         "certificate_file": SimpleUploadedFile("cert.pem", cert_pem),
                                         "key_file": SimpleUploadedFile("key.pem", privkey_pem),
                                         "key_password": privkey_password.decode("utf-8")},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        push_certificate = PushCertificate.objects.get(name=name)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "created")
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(new_value["certificate_sha256"],
                         hashlib.sha256(bytes(push_certificate.certificate)).hexdigest())
        self.assert_no_key_material(event, push_certificate)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_upload_push_certificate_certificate_audit_event(self, post_event):
        # the audit value of the fingerprint: it changes when the certificate is replaced
        push_certificate = force_push_certificate()
        push_certificate.topic = None
        push_certificate.save()
        prev_fingerprint = hashlib.sha256(bytes(push_certificate.certificate)).hexdigest()
        topic = get_random_string(12)
        cert_pem, privkey_pem, _ = force_push_certificate_material(topic=topic, encrypt_key=False)
        push_certificate.set_private_key(privkey_pem)
        push_certificate.save()
        self.login("mdm.change_pushcertificate", "mdm.view_pushcertificate")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(
                reverse("mdm:upload_push_certificate_certificate", args=(push_certificate.pk,)),
                {"name": push_certificate.name,
                 "certificate_file": SimpleUploadedFile("cert.pem", cert_pem)},
                follow=True)
        self.assertEqual(response.status_code, 200)
        push_certificate.refresh_from_db()
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "updated")
        prev_value = event.payload["object"]["prev_value"]
        new_value = event.payload["object"]["new_value"]
        self.assertEqual(prev_value["certificate_sha256"], prev_fingerprint)
        self.assertEqual(new_value["certificate_sha256"],
                         hashlib.sha256(bytes(push_certificate.certificate)).hexdigest())
        self.assertNotEqual(prev_value["certificate_sha256"], new_value["certificate_sha256"])
        self.assertIsNone(prev_value["topic"])
        self.assertEqual(new_value["topic"], topic)
        self.assert_no_key_material(event, push_certificate)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_push_certificate_audit_event(self, post_event):
        push_certificate = force_push_certificate(with_material=True)
        self.login("mdm.delete_pushcertificate", "mdm.view_pushcertificate")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("mdm:delete_push_certificate", args=(push_certificate.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "deleted")
        self.assertEqual(event.payload["object"]["prev_value"]["name"], push_certificate.name)
        self.assert_no_key_material(event, push_certificate)

    def assert_no_key_material(self, event, push_certificate):
        serialized = json.dumps(event.payload)
        self.assertNotIn("private_key", serialized)
        self.assertNotIn(push_certificate.private_key, serialized)

    # DEP virtual server

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_dep_virtual_server_audit_event(self, post_event):
        # UpdateDEPVirtualServerForm only offers the enrollments of that virtual server, so the
        # enrollment force helper, which makes its own, will not do here
        enrollment = force_dep_enrollment(self.mbu)
        virtual_server = enrollment.virtual_server
        # the fixture leaves the token secrets unset, so set one to make the assertion below bite
        virtual_server.token.set_access_secret(get_random_string(12))
        virtual_server.token.save()
        self.login("mdm.change_depvirtualserver", "mdm.view_depvirtualserver")
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("mdm:update_dep_virtual_server", args=(virtual_server.pk,)),
                                        {"default_enrollment": enrollment.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        event = self.get_audit_event(post_event)
        self.assertEqual(event.payload["action"], "updated")
        self.assertEqual(event.payload["object"]["model"], "mdm.depvirtualserver")
        # default_enrollment is the only editable field, so without it in the serialization the
        # prev_value and the new_value would have matched
        self.assertIsNone(event.payload["object"]["prev_value"]["default_enrollment"])
        self.assertEqual(event.payload["object"]["new_value"]["default_enrollment"]["pk"], enrollment.pk)
        self.assertNotIn(virtual_server.token.access_secret, json.dumps(event.payload))
