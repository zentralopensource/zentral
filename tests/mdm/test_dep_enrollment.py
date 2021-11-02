import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from realms.models import Realm, RealmUser
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.mdm.models import (DEPEnrollment, DEPEnrollmentSession,
                                        DEPOrganization, DEPToken, DEPVirtualServer,
                                        PushCertificate, SCEPConfig)
from zentral.contrib.mdm.payloads import build_scep_payload


class TestDEPEnrollment(TestCase):
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

    def _force_scep_config(self):
        scep_config = SCEPConfig(
            name=get_random_string(12),
            url="https://example.com/{}".format(get_random_string(12)),
            challenge_type="STATIC",
            challenge_kwargs={"challenge": get_random_string(12)}
        )
        scep_config.set_challenge_kwargs({"challenge": get_random_string(12)})
        scep_config.save()
        return scep_config

    def _force_dep_virtual_server(self):
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
            uuid=uuid.uuid4(),
            organization=dep_organization,
            token=dep_token
        )

    def _force_dep_enrollment(self):
        return DEPEnrollment.objects.create(
            name=get_random_string(12),
            uuid=uuid.uuid4(),
            push_certificate=self._force_push_certificate(),
            scep_config=self._force_scep_config(),
            virtual_server=self._force_dep_virtual_server(),
            enrollment_secret=EnrollmentSecret.objects.create(meta_business_unit=self.mbu),
            skip_setup_items=[p for p, _ in DEPEnrollment.SKIPPABLE_SETUP_PANE_CHOICES],
        )

    def test_create_dep_enrollment_session(self):
        enrollment = self._force_dep_enrollment()
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        self.assertEqual(session.get_enrollment(), enrollment)
        self.assertEqual(session.status, "STARTED")

    def test_dep_enrollment_session_scep_payload(self):
        enrollment = self._force_dep_enrollment()
        session = DEPEnrollmentSession.objects.create_from_dep_enrollment(
            enrollment, get_random_string(12), str(uuid.uuid4())
        )
        scep_payload = build_scep_payload(session)
        self.assertEqual(scep_payload["PayloadContent"]["Challenge"],
                         enrollment.scep_config.get_challenge_kwargs()["challenge"])
