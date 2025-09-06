from unittest.mock import patch
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.cert_issuer_backends import CertIssuerBackend
from zentral.contrib.mdm.models import SCEPIssuer
from zentral.contrib.mdm.provisioning import SCEPIssuerProvisioner
from .utils import force_scep_issuer


class MDMSCEPIssuerProvisioningTestCase(TestCase):
    @property
    def app_config(self):
        return apps.get_app_config("mdm")

    @staticmethod
    def fake_app_settings(**uid_spec_d):
        return {
            "apps": {
                "zentral.contrib.mdm": {
                    "provisioning": {
                        "scep_issuers": uid_spec_d
                    }
                }
            }
        }

    # model

    def test_provisioner_model(self):
        self.assertEqual(SCEPIssuerProvisioner(self.app_config, {}).model, SCEPIssuer)

    def test_unknown_scep_issuer(self):
        force_scep_issuer()
        self.assertIsNone(SCEPIssuerProvisioner(self.app_config, {}).get_instance_by_uid("yolo"))

    def test_existing_scep_issuer(self):
        uid = get_random_string(12)
        scep_issuer = force_scep_issuer(provisioning_uid=uid)
        self.assertEqual(
            SCEPIssuerProvisioner(self.app_config, {}).get_instance_by_uid(uid),
            scep_issuer,
        )

    # serializer

    def test_serializer_full_serialization(self):
        scep_issuer = force_scep_issuer()
        serializer = SCEPIssuerProvisioner.serializer_class(scep_issuer)
        self.assertEqual(
            serializer.data,
            {'id': str(scep_issuer.pk),
             'provisioning_uid': None,
             'name': scep_issuer.name,
             'description': '',
             'url': scep_issuer.url,
             'key_usage': 0,
             'key_size': 2048,
             'backend': 'STATIC_CHALLENGE',
             'static_challenge_kwargs': {
                 'challenge': scep_issuer.get_backend_kwargs()['challenge']
              },
             'version': 1,
             'created_at': scep_issuer.created_at.isoformat(),
             'updated_at': scep_issuer.updated_at.isoformat()}
        )

    def test_serializer_reduced_serialization(self):
        provisioning_uid = get_random_string(12)
        scep_issuer = force_scep_issuer(provisioning_uid=provisioning_uid)
        serializer = SCEPIssuerProvisioner.serializer_class(scep_issuer)
        self.assertEqual(
            serializer.data,
            {'id': str(scep_issuer.pk),
             'provisioning_uid': provisioning_uid,
             'name': scep_issuer.name,
             'description': '',
             'url': scep_issuer.url,
             'key_usage': 0,
             'key_size': 2048,
             'version': 1,
             'created_at': scep_issuer.created_at.isoformat(),
             'updated_at': scep_issuer.updated_at.isoformat()}
        )

    def test_serializer_required_fields(self):
        serializer = SCEPIssuerProvisioner.serializer_class(data={})
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'name': ['This field is required.'],
             'url': ['This field is required.'],
             'backend': ['This field is required.']}
        )

    def test_serializer_unknown_backend(self):
        serializer = SCEPIssuerProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "backend": "YOLO",
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'backend': ['"YOLO" is not a valid choice.']}
        )

    def test_serializer_missing_backend_kwargs(self):
        i = 0
        for cert_issuer_backend in CertIssuerBackend:
            i += 1
            serializer = SCEPIssuerProvisioner.serializer_class(data={
                "name": "yolo",
                "url": "https://www.example.com/scep/",
                "backend": cert_issuer_backend.value,
            })
            serializer.is_valid()
            self.assertEqual(
                serializer.errors,
                {f"{cert_issuer_backend.value.lower()}_kwargs": ["This field is required."]}
            )
        self.assertTrue(i > 0)

    def test_serializer_static_challenge_required_fields(self):
        serializer = SCEPIssuerProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "backend": "STATIC_CHALLENGE",
            "static_challenge_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'static_challenge_kwargs': {'challenge': ['This field is required.']}},
        )

    def test_serializer_microsoft_ca_required_fields(self):
        serializer = SCEPIssuerProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "backend": "MICROSOFT_CA",
            "microsoft_ca_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'microsoft_ca_kwargs': {
                'url': ['This field is required.'],
                'username': ['This field is required.'],
                'password': ['This field is required.']}}
        )

    def test_serializer_okta_ca_required_fields(self):
        serializer = SCEPIssuerProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "backend": "OKTA_CA",
            "okta_ca_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'okta_ca_kwargs': {
                'url': ['This field is required.'],
                'username': ['This field is required.'],
                'password': ['This field is required.']}}
        )

    # settings

    def test_no_app_settings(self):
        self.assertEqual(SCEPIssuerProvisioner(self.app_config, {}).app_settings, {})

    def test_app_settings(self):
        self.assertEqual(
            SCEPIssuerProvisioner(
                self.app_config,
                {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}}
            ).app_settings,
            {"yolo": "fomo"},
        )

    def test_no_app_settings_no_uid_spec(self):
        self.assertEqual(list(SCEPIssuerProvisioner(self.app_config, {}).iter_uid_spec()), [])

    def test_app_settings_no_provisioning_no_uid_spec(self):
        self.assertEqual(
            list(
                SCEPIssuerProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_no_config_key_no_uid_spec(self):
        self.assertEqual(
            list(
                SCEPIssuerProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"provisioning": {"yolo": {}}}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_uid_spec(self):
        self.assertEqual(
            list(
                SCEPIssuerProvisioner(
                    self.app_config,
                    self.fake_app_settings(yolo={"un": 1}, fomo={"deux": 2})
                ).iter_uid_spec()
            ),
            [("yolo", {"un": 1}), ("fomo", {"deux": 2})]
        )

    # create

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_scep_issuer_static_challenge_exception(self, logger_exception):
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "STATIC_CHALLENGE",
                    # missing static_challenge_kwargs
                }
            )
        ).apply()
        self.assertEqual(SCEPIssuer.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            SCEPIssuer, "yolo"
        )

    def test_create_scep_issuer_static_challenge_backend(self):
        qs = SCEPIssuer.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "STATIC_CHALLENGE",
                    "static_challenge_kwargs": {
                        "challenge": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_issuer = qs.first()
        self.assertEqual(scep_issuer.provisioning_uid, "yolo")
        self.assertEqual(scep_issuer.backend, CertIssuerBackend.StaticChallenge.value)
        self.assertEqual(scep_issuer.get_backend_kwargs(), {"challenge": "FoMo"})

    def test_create_scep_issuer_microsoft_ca_backend(self):
        qs = SCEPIssuer.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "MICROSOFT_CA",
                    "microsoft_ca_kwargs": {
                        "url": "https://www.example.com/ndes/",
                        "username": "YoLo",
                        "password": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_issuer = qs.first()
        self.assertEqual(scep_issuer.provisioning_uid, "yolo")
        self.assertEqual(scep_issuer.backend, CertIssuerBackend.MicrosoftCA.value)
        self.assertEqual(
            scep_issuer.get_backend_kwargs(),
            {"url": "https://www.example.com/ndes/",
             "username": "YoLo",
             "password": "FoMo"}
        )

    def test_create_scep_issuer_okta_ca_backend(self):
        qs = SCEPIssuer.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "OKTA_CA",
                    "okta_ca_kwargs": {
                        "url": "https://www.example.com/ndes/",
                        "username": "YoLo",
                        "password": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_issuer = qs.first()
        self.assertEqual(scep_issuer.provisioning_uid, "yolo")
        self.assertEqual(scep_issuer.backend, CertIssuerBackend.OktaCA.value)
        self.assertEqual(
            scep_issuer.get_backend_kwargs(),
            {"url": "https://www.example.com/ndes/",
             "username": "YoLo",
             "password": "FoMo"}
        )

    # update

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_scep_issuer_static_challenge_exception(self, logger_exception):
        scep_issuer = force_scep_issuer(provisioning_uid="yolo")
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "STATIC_CHALLENGE",
                    # missing static_challenge_kwargs
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            SCEPIssuer, "yolo"
        )
        scep_issuer.refresh_from_db()
        self.assertNotEqual(scep_issuer.name, "Name")

    def test_update_scep_issuer_static_challenge(self):
        scep_issuer = force_scep_issuer(provisioning_uid="yolo")
        qs = SCEPIssuer.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(scep_issuer.get_backend_kwargs()["challenge"], "FoMo")
        SCEPIssuerProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "backend": "STATIC_CHALLENGE",
                    "static_challenge_kwargs": {
                        "challenge": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), scep_issuer)
        scep_issuer = qs.first()
        self.assertEqual(scep_issuer.provisioning_uid, "yolo")
        self.assertEqual(scep_issuer.backend, CertIssuerBackend.StaticChallenge.value)
        self.assertEqual(scep_issuer.get_backend_kwargs(), {"challenge": "FoMo"})
