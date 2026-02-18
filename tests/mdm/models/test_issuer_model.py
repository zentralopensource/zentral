
from django.test import TestCase

from tests.mdm.utils import force_acme_issuer
from zentral.contrib.mdm.cert_issuer_backends import CertIssuerBackend


class MDMIssuerModelTestCase(TestCase):

    @classmethod
    def setUpTestData(cls):
        cls.issuer = force_acme_issuer(backend=CertIssuerBackend.IDent)

    def test_issuer_serialize_for_event(self):
        keys_only = self.issuer.serialize_for_event(keys_only=True)

        self.assertEqual(
            keys_only, {"pk": str(self.issuer.pk), "name": self.issuer.name}
        )

        self.issuer.provisioning_uid = "profUid"
        all_keys = self.issuer.serialize_for_event(keys_only=False)

        backend_kwargs = self.issuer.get_backend_kwargs_for_event()
        self.assertEqual(
            all_keys,
            {
                "pk": str(self.issuer.pk),
                "name": self.issuer.name,
                "attest": True,
                "backend": "IDENT",
                "backend_kwargs": backend_kwargs,
                "created_at": self.issuer.created_at,
                "description": "",
                "directory_url": self.issuer.directory_url,
                "extended_key_usage": [],
                "hardware_bound": True,
                "key_size": 384,
                "key_type": "ECSECPrimeRandom",
                "updated_at": self.issuer.updated_at,
                "version": 1,
                "usage_flags": 1,
                "provisioning_uid": "profUid",
            },
        )
