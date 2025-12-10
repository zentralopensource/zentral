import plistlib
from unittest.mock import Mock, patch
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.crypto import verify_signed_payload
from zentral.contrib.mdm.events import UserEnrollmentRequestEvent
from zentral.contrib.mdm.models import UserEnrollmentSession
from zentral.contrib.mdm.public_views.user import user_enroll_callback
from zentral.contrib.inventory.models import MetaBusinessUnit
from .utils import force_realm_user, force_user_enrollment


@patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
class MDMUserEnrollmentPublicViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.realm, cls.realm_user = force_realm_user()

    def assertAbort(self, post_event, reason, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, UserEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "failure")
        self.assertEqual(last_event.payload["reason"], reason)
        for k, v in kwargs.items():
            if k == "serial_number":
                self.assertEqual(last_event.metadata.machine_serial_number, v)
            else:
                self.assertEqual(last_event.payload.get(k), v)

    def assertSuccess(self, post_event, **kwargs):
        last_event = post_event.call_args.args[0]
        self.assertIsInstance(last_event, UserEnrollmentRequestEvent)
        self.assertEqual(last_event.payload["status"], "success")
        for k, v in kwargs.items():
            self.assertEqual(last_event.payload.get(k), v)

    # service discovery

    def test_service_discovery(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        response = self.client.get(reverse("mdm_public:user_enrollment_service_discovery",
                                           args=(enrollment.enrollment_secret.secret,)))
        self.assertEqual(
            response.json(),
            {'Servers': [{'Version': 'mdm-byod',
                          'BaseURL': 'https://zentral' + reverse("mdm_public:enroll_user",
                                                                 args=(enrollment.enrollment_secret.secret,))}]}
        )

    # enroll user view

    def test_enroll_user_unknown_secret(self, post_event):
        response = self.client.post(reverse("mdm_public:enroll_user", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "secret verification failed: 'unknown secret'")

    def test_enroll_user_no_realm(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        enrollment.realm = None  # Should never happen
        enrollment.save()
        response = self.client.post(reverse("mdm_public:enroll_user", args=(enrollment.enrollment_secret.secret,)))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "This user enrollment has no realm")

    def test_enroll_user_no_authorization(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        self.assertEqual(enrollment.userenrollmentsession_set.count(), 0)
        response = self.client.post(reverse("mdm_public:enroll_user", args=(enrollment.enrollment_secret.secret,)))
        self.assertEqual(response.status_code, 401)
        self.assertEqual(enrollment.userenrollmentsession_set.count(), 1)
        enrollment_session = enrollment.userenrollmentsession_set.first()
        self.assertEqual(enrollment_session.status, "ACCOUNT_DRIVEN_START")
        auth_url = "https://zentral" + reverse("mdm_public:authenticate_user",
                                               args=(enrollment_session.enrollment_secret.secret,))
        self.assertEqual(response.headers["WWW-Authenticate"], f'Bearer method="apple-as-web" url="{auth_url}"')

    def test_enroll_user_invalid_access_token(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        _, realm_user = force_realm_user(self.realm)
        enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        self.assertIsNone(enrollment_session.access_token)
        enrollment_session.set_account_driven_authenticated_status(realm_user)
        self.assertIsNotNone(enrollment_session.access_token)
        response = self.client.post(
            reverse("mdm_public:enroll_user", args=(enrollment.enrollment_secret.secret,)),
            headers={"Authorization": "Bearer " + get_random_string(12)}
        )
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "Invalid access token")

    def test_enroll_user(self, post_event):
        display_name = get_random_string(12)
        enrollment = force_user_enrollment(self.mbu, self.realm, enrollment_display_name=display_name)
        _, realm_user = force_realm_user(self.realm)
        enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        enrollment_session.set_account_driven_authenticated_status(realm_user)
        response = self.client.post(
            reverse("mdm_public:enroll_user", args=(enrollment.enrollment_secret.secret,)),
            headers={"Authorization": f"Bearer {enrollment_session.access_token}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertSuccess(post_event)
        _, data = verify_signed_payload(response.content)
        payload = plistlib.loads(data)
        self.assertEqual(payload["PayloadOrganization"], display_name)
        mdm_payload = [p for p in payload["PayloadContent"] if p["PayloadType"] == "com.apple.mdm"][0]
        self.assertEqual(mdm_payload["AssignedManagedAppleID"], realm_user.email)
        self.assertEqual(mdm_payload["EnrollmentMode"], "BYOD")
        scep_payload = [p for p in payload["PayloadContent"] if p["PayloadType"] == "com.apple.security.scep"][0]
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_issuer.get_backend_kwargs()["challenge"])

    # authenticate user view

    def test_authenticate_user_unknown_secret(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        response = self.client.get(reverse("mdm_public:authenticate_user", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "secret verification failed: 'unknown secret'")

    def test_authenticate_user_no_realm(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        enrollment.realm = None  # Should never happen
        enrollment.save()
        enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        response = self.client.get(
            reverse("mdm_public:authenticate_user", args=(enrollment_session.enrollment_secret.secret,))
        )
        self.assertEqual(response.status_code, 400)
        self.assertAbort(post_event, "This user enrollment has no realm")

    def test_authenticate_user(self, post_event):
        enrollment = force_user_enrollment(self.mbu, self.realm)
        enrollment_session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        self.assertIsNone(enrollment_session.access_token)
        response = self.client.get(
            reverse("mdm_public:authenticate_user", args=(enrollment_session.enrollment_secret.secret,))
        )
        self.assertEqual(response.status_code, 302)
        realm = enrollment.realm
        ras = realm.realmauthenticationsession_set.first()
        self.assertEqual(response.url, f"/public/realms/{realm.pk}/ldap/{ras.pk}/login/")
        self.assertEqual(ras.callback, "zentral.contrib.mdm.public_views.user.user_enroll_callback")
        self.assertEqual(ras.callback_kwargs, {"user_enrollment_session_pk": enrollment_session.pk})
        enrollment_session.refresh_from_db()
        self.assertIsNone(enrollment_session.access_token)
        self.assertEqual(enrollment_session.status, "ACCOUNT_DRIVEN_START")
        # fake the realm auth
        _, ras.user = force_realm_user(realm)
        request = Mock()
        request.session = self.client.session
        response = user_enroll_callback(request, ras, enrollment_session.pk)
        enrollment_session.refresh_from_db()
        self.assertIsNotNone(enrollment_session.access_token)
        self.assertEqual(enrollment_session.status, "ACCOUNT_DRIVEN_AUTHENTICATED")
        self.assertEqual(response.status_code, 308)
        self.assertEqual(
            response.url,
            "apple-remotemanagement-user-login://authentication-results?access-token="
            + enrollment_session.access_token
        )
