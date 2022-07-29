from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import UserEnrollment, UserEnrollmentSession, PushCertificate, SCEPConfig
from zentral.contrib.mdm.payloads import build_scep_payload


class TestUserEnrollment(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        cls.mbu.create_enrollment_business_unit()
        cls.realm = Realm.objects.create(
            name=get_random_string(12),
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        username = get_random_string(12)
        email = f"{username}@example.com"
        cls.realm_user = RealmUser.objects.create(
            realm=cls.realm,
            claims={"username": username,
                    "email": email},
            username=username,
            email=email,
        )

    def _force_push_certificate(self):
        return PushCertificate.objects.create(
            name=get_random_string(12),
            topic=get_random_string(12),
            not_before="2000-01-01",
            not_after="2040-01-01",
            certificate=b"1",
            private_key=b"2",
        )

    def _force_scep_config(self):
        return SCEPConfig.objects.create(
            name=get_random_string(12),
            url="https://example.com/{}".format(get_random_string(12)),
            challenge_type="STATIC",
            challenge_kwargs={"challenge": get_random_string(12)}
        )

    def _force_user_enrollment(self):
        return UserEnrollment.objects.create(
            push_certificate=self._force_push_certificate(),
            realm=self.realm,
            scep_config=self._force_scep_config(),
            name=get_random_string(12),
            enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        )

    def test_create_user_enrollment_session_no_managed_apple_id(self):
        enrollment = self._force_user_enrollment()
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "ACCOUNT_DRIVEN_START")

    def test_user_enrollment_session_scep_payload(self):
        enrollment = self._force_user_enrollment()
        session = UserEnrollmentSession.objects.create_from_user_enrollment(enrollment)
        session.set_account_driven_authenticated_status(self.realm_user)
        session.set_started_status()
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_config.challenge_kwargs["challenge"])
