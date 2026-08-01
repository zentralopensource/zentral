import json
import uuid
from unittest.mock import Mock, patch

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import MetaBusinessUnit
from zentral.contrib.mdm.dep_client import DEPClientError
from zentral.core.events.base import AuditEvent

from .utils import (force_acme_issuer, force_ota_enrollment, force_push_certificate,
                    force_dep_virtual_server, force_realm, force_scep_issuer,
                    force_user_enrollment)


class EnrollmentAuditEventTestCase(TestCase, LoginCase):
    """An enrollment is the path onto the MDM, so creating, updating or revoking one has to
    leave a trail. The behaviour of the views is covered by the per view test cases; this
    only checks the events, and that the enrollment secret never reaches them."""

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

    def assert_audit_event(self, post_event, action, model, pk, index=0):
        event = post_event.call_args_list[index].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(event.payload["action"], action)
        self.assertEqual(event.payload["object"]["model"], model)
        self.assertEqual(event.payload["object"]["pk"], str(pk))
        return event

    def assert_no_secret(self, event, enrollment):
        # EnrollmentSecret.serialize_for_event() leaves the secret out; the enrollment is the
        # way onto the MDM, so a regression there would put a live credential in every store
        self.assertNotIn(enrollment.enrollment_secret.secret, json.dumps(event.payload))

    # OTA enrollments

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_ota_enrollment_audit_event(self, post_event):
        self.login("mdm.add_otaenrollment", "mdm.view_otaenrollment")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_ota_enrollment"),
                                        {"oe-name": name,
                                         "oe-display_name": get_random_string(12),
                                         "oe-acme_issuer": force_acme_issuer().pk,
                                         "oe-scep_issuer": force_scep_issuer().pk,
                                         "oe-push_certificate": force_push_certificate().pk,
                                         "es-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        enrollment = response.context["object"]
        event = self.assert_audit_event(post_event, "created", "mdm.otaenrollment", enrollment.pk)
        self.assertEqual(event.payload["object"]["new_value"]["name"], name)
        self.assert_no_secret(event, enrollment)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_ota_enrollment_audit_event(self, post_event):
        enrollment = force_ota_enrollment(self.mbu)
        prev_name = enrollment.name
        new_name = get_random_string(12)
        self.login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_ota_enrollment", args=(enrollment.pk,)),
                                        {"oe-name": new_name,
                                         "oe-display_name": get_random_string(12),
                                         "oe-scep_issuer": enrollment.scep_issuer.pk,
                                         "oe-push_certificate": enrollment.push_certificate.pk,
                                         "es-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        event = self.assert_audit_event(post_event, "updated", "mdm.otaenrollment", enrollment.pk)
        # the prev_value has to be serialized before the forms validate, or it would already
        # carry the posted name
        self.assertEqual(event.payload["object"]["prev_value"]["name"], prev_name)
        self.assertEqual(event.payload["object"]["new_value"]["name"], new_name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_revoke_ota_enrollment_audit_event(self, post_event):
        enrollment = force_ota_enrollment(self.mbu)
        self.assertIsNone(enrollment.enrollment_secret.revoked_at)
        self.login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        event = self.assert_audit_event(post_event, "updated", "mdm.otaenrollment", enrollment.pk)
        prev_secret = event.payload["object"]["prev_value"]["enrollment_secret"]
        new_secret = event.payload["object"]["new_value"]["enrollment_secret"]
        self.assertFalse(prev_secret["is_revoked"])
        self.assertTrue(new_secret["is_revoked"])
        self.assertIsNotNone(new_secret["revoked_at"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_revoke_revoked_ota_enrollment_posts_no_event(self, post_event):
        enrollment = force_ota_enrollment(self.mbu)
        enrollment.revoke()
        self.login("mdm.change_otaenrollment", "mdm.view_otaenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:revoke_ota_enrollment", args=(enrollment.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    # user enrollments

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_user_enrollment_audit_event(self, post_event):
        self.login("mdm.add_userenrollment", "mdm.view_userenrollment")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_user_enrollment"),
                                        {"ue-name": name,
                                         "ue-display_name": get_random_string(12),
                                         "ue-realm": force_realm().pk,
                                         "ue-scep_issuer": force_scep_issuer().pk,
                                         "ue-push_certificate": force_push_certificate().pk,
                                         "es-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        enrollment = response.context["object"]
        event = self.assert_audit_event(post_event, "created", "mdm.userenrollment", enrollment.pk)
        self.assertEqual(event.payload["object"]["new_value"]["name"], name)
        self.assert_no_secret(event, enrollment)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_user_enrollment_audit_event(self, post_event):
        enrollment = force_user_enrollment(self.mbu)
        prev_name = enrollment.name
        new_name = get_random_string(12)
        self.login("mdm.change_userenrollment", "mdm.view_userenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_user_enrollment", args=(enrollment.pk,)),
                                        {"ue-name": new_name,
                                         "ue-display_name": get_random_string(12),
                                         "ue-realm": force_realm().pk,
                                         "ue-scep_issuer": enrollment.scep_issuer.pk,
                                         "ue-push_certificate": enrollment.push_certificate.pk,
                                         "es-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        event = self.assert_audit_event(post_event, "updated", "mdm.userenrollment", enrollment.pk)
        self.assertEqual(event.payload["object"]["prev_value"]["name"], prev_name)
        self.assertEqual(event.payload["object"]["new_value"]["name"], new_name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_revoke_user_enrollment_audit_event(self, post_event):
        enrollment = force_user_enrollment(self.mbu)
        self.login("mdm.change_userenrollment", "mdm.view_userenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:revoke_user_enrollment", args=(enrollment.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        event = self.assert_audit_event(post_event, "updated", "mdm.userenrollment", enrollment.pk)
        self.assertTrue(event.payload["object"]["new_value"]["enrollment_secret"]["is_revoked"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_revoke_revoked_user_enrollment_posts_no_event(self, post_event):
        enrollment = force_user_enrollment(self.mbu)
        enrollment.revoke()
        self.login("mdm.change_userenrollment", "mdm.view_userenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:revoke_user_enrollment", args=(enrollment.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()

    # DEP enrollments

    @patch("zentral.contrib.mdm.dep.DEPClient.from_dep_virtual_server")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_audit_event(self, post_event, from_dep_virtual_server):
        client = Mock()
        client.add_profile.return_value = {
            "profile_uuid": str(uuid.uuid4()).upper().replace("-", ""),
            "devices": {},
        }
        from_dep_virtual_server.return_value = client
        self.login("mdm.add_depenrollment", "mdm.view_depenrollment")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                        {"de-name": name,
                                         "de-display_name": get_random_string(12),
                                         "de-scep_issuer": force_scep_issuer().pk,
                                         "de-push_certificate": force_push_certificate().pk,
                                         "de-virtual_server": force_dep_virtual_server().pk,
                                         "de-is_mdm_removable": "on",
                                         "de-is_supervised": "",
                                         "de-admin_password_complexity": 3,
                                         "de-admin_password_rotation_delay": 60,
                                         "es-meta_business_unit": self.mbu.pk},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        enrollment = response.context["object"]
        event = self.assert_audit_event(post_event, "created", "mdm.depenrollment", enrollment.pk)
        self.assertEqual(event.payload["object"]["new_value"]["name"], name)
        self.assert_no_secret(event, enrollment)

    @patch("zentral.contrib.mdm.views.dep_enrollments.define_dep_profile")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_dep_enrollment_dep_error_posts_no_event(self, post_event, define_dep_profile):
        define_dep_profile.side_effect = DEPClientError("Boom")
        self.login("mdm.add_depenrollment", "mdm.view_depenrollment")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_dep_enrollment"),
                                        {"de-name": get_random_string(12),
                                         "de-display_name": get_random_string(12),
                                         "de-scep_issuer": force_scep_issuer().pk,
                                         "de-push_certificate": force_push_certificate().pk,
                                         "de-virtual_server": force_dep_virtual_server().pk,
                                         "de-is_mdm_removable": "on",
                                         "de-is_supervised": "",
                                         "de-admin_password_complexity": 3,
                                         "de-admin_password_rotation_delay": 60,
                                         "es-meta_business_unit": self.mbu.pk})
        self.assertEqual(response.status_code, 200)
        self.assertFormError(response.context["dep_enrollment_form"], None, "Boom")
        # the enrollment is only persisted by define_dep_profile(), so a failed call to Apple
        # must not leave a created event behind
        self.assertEqual(len(callbacks), 0)
        post_event.assert_not_called()
