from unittest.mock import patch
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.models import SCEPConfig, SCEPChallengeType
from zentral.contrib.mdm.provisioning import SCEPConfigProvisioner
from .utils import force_scep_config


class MDMSCEPConfigProvisioningTestCase(TestCase):
    @property
    def app_config(self):
        return apps.get_app_config("mdm")

    @staticmethod
    def fake_app_settings(**uid_spec_d):
        return {
            "apps": {
                "zentral.contrib.mdm": {
                    "provisioning": {
                        "scep_configs": uid_spec_d
                    }
                }
            }
        }

    # model

    def test_provisioner_model(self):
        self.assertEqual(SCEPConfigProvisioner(self.app_config, {}).model, SCEPConfig)

    def test_unknown_scep_config(self):
        force_scep_config()
        self.assertIsNone(SCEPConfigProvisioner(self.app_config, {}).get_instance_by_uid("yolo"))

    def test_existing_scep_config(self):
        uid = get_random_string(12)
        scep_config = force_scep_config(provisioning_uid=uid)
        self.assertEqual(
            SCEPConfigProvisioner(self.app_config, {}).get_instance_by_uid(uid),
            scep_config,
        )

    # serializer

    def test_serializer_full_serialization(self):
        scep_config = force_scep_config()
        serializer = SCEPConfigProvisioner.serializer_class(scep_config)
        self.assertEqual(
            serializer.data,
            {'id': scep_config.pk,
             'provisioning_uid': None,
             'name': scep_config.name,
             'url': scep_config.url,
             'key_usage': 0,
             'key_is_extractable': False,
             'keysize': 2048,
             'allow_all_apps_access': False,
             'challenge_type': 'STATIC',
             'microsoft_ca_challenge_kwargs': None,
             'okta_ca_challenge_kwargs': None,
             'static_challenge_kwargs': {
                 'challenge': scep_config.get_challenge_kwargs()['challenge']
              },
             'created_at': scep_config.created_at.isoformat(),
             'updated_at': scep_config.updated_at.isoformat()}
        )

    def test_serializer_reduced_serialization(self):
        provisioning_uid = get_random_string(12)
        scep_config = force_scep_config(provisioning_uid=provisioning_uid)
        serializer = SCEPConfigProvisioner.serializer_class(scep_config)
        self.assertEqual(
            serializer.data,
            {'id': scep_config.pk,
             'provisioning_uid': provisioning_uid,
             'name': scep_config.name,
             'url': scep_config.url,
             'key_usage': 0,
             'key_is_extractable': False,
             'keysize': 2048,
             'allow_all_apps_access': False,
             'created_at': scep_config.created_at.isoformat(),
             'updated_at': scep_config.updated_at.isoformat()}
        )

    def test_serializer_required_fields(self):
        serializer = SCEPConfigProvisioner.serializer_class(data={})
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'name': ['This field is required.'],
             'url': ['This field is required.'],
             'challenge_type': ['This field is required.']}
        )

    def test_serializer_unknown_challenge_type(self):
        serializer = SCEPConfigProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "challenge_type": "YOLO",
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'challenge_type': ['"YOLO" is not a valid choice.']}
        )

    def test_serializer_missing_challenge_kwargs(self):
        i = 0
        for challenge_type in SCEPChallengeType:
            i += 1
            serializer = SCEPConfigProvisioner.serializer_class(data={
                "name": "yolo",
                "url": "https://www.example.com/scep/",
                "challenge_type": challenge_type.name,
            })
            serializer.is_valid()
            self.assertEqual(
                serializer.errors,
                {f"{challenge_type.name.lower()}_challenge_kwargs": ["This field is required."]}
            )
        self.assertTrue(i > 0)

    def test_serializer_static_challenge_required_fields(self):
        serializer = SCEPConfigProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "challenge_type": "STATIC",
            "static_challenge_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'static_challenge_kwargs': {'challenge': ['This field is required.']}},
        )

    def test_serializer_microsoft_ca_challenge_required_fields(self):
        serializer = SCEPConfigProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "challenge_type": "MICROSOFT_CA",
            "microsoft_ca_challenge_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'microsoft_ca_challenge_kwargs': {
                'url': ['This field is required.'],
                'username': ['This field is required.'],
                'password': ['This field is required.']}}
        )

    def test_serializer_okta_ca_challenge_required_fields(self):
        serializer = SCEPConfigProvisioner.serializer_class(data={
            "name": "yolo",
            "url": "https://www.example.com/scep/",
            "challenge_type": "OKTA_CA",
            "okta_ca_challenge_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'okta_ca_challenge_kwargs': {
                'url': ['This field is required.'],
                'username': ['This field is required.'],
                'password': ['This field is required.']}}
        )

    # settings

    def test_no_app_settings(self):
        self.assertEqual(SCEPConfigProvisioner(self.app_config, {}).app_settings, {})

    def test_app_settings(self):
        self.assertEqual(
            SCEPConfigProvisioner(
                self.app_config,
                {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}}
            ).app_settings,
            {"yolo": "fomo"},
        )

    def test_no_app_settings_no_uid_spec(self):
        self.assertEqual(list(SCEPConfigProvisioner(self.app_config, {}).iter_uid_spec()), [])

    def test_app_settings_no_provisioning_no_uid_spec(self):
        self.assertEqual(
            list(
                SCEPConfigProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_no_config_key_no_uid_spec(self):
        self.assertEqual(
            list(
                SCEPConfigProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"provisioning": {"yolo": {}}}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_uid_spec(self):
        self.assertEqual(
            list(
                SCEPConfigProvisioner(
                    self.app_config,
                    self.fake_app_settings(yolo={"un": 1}, fomo={"deux": 2})
                ).iter_uid_spec()
            ),
            [("yolo", {"un": 1}), ("fomo", {"deux": 2})]
        )

    # create

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_scep_config_static_challenge_exception(self, logger_exception):
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "STATIC",
                    # missing static_challenge_kwargs
                }
            )
        ).apply()
        self.assertEqual(SCEPConfig.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            SCEPConfig, "yolo"
        )

    def test_create_scep_config_static_challenge(self):
        qs = SCEPConfig.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "STATIC",
                    "static_challenge_kwargs": {
                        "challenge": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_config = qs.first()
        self.assertEqual(scep_config.provisioning_uid, "yolo")
        self.assertEqual(scep_config.challenge_type, SCEPChallengeType.STATIC.name)
        self.assertEqual(scep_config.get_challenge_kwargs(), {"challenge": "FoMo"})

    def test_create_scep_config_microsoft_ca_challenge(self):
        qs = SCEPConfig.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "MICROSOFT_CA",
                    "microsoft_ca_challenge_kwargs": {
                        "url": "https://www.example.com/ndes/",
                        "username": "YoLo",
                        "password": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_config = qs.first()
        self.assertEqual(scep_config.provisioning_uid, "yolo")
        self.assertEqual(scep_config.challenge_type, SCEPChallengeType.MICROSOFT_CA.name)
        self.assertEqual(
            scep_config.get_challenge_kwargs(),
            {"url": "https://www.example.com/ndes/",
             "username": "YoLo",
             "password": "FoMo"}
        )

    def test_create_scep_config_okta_ca_challenge(self):
        qs = SCEPConfig.objects.all()
        self.assertEqual(qs.count(), 0)
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "OKTA_CA",
                    "okta_ca_challenge_kwargs": {
                        "url": "https://www.example.com/ndes/",
                        "username": "YoLo",
                        "password": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        scep_config = qs.first()
        self.assertEqual(scep_config.provisioning_uid, "yolo")
        self.assertEqual(scep_config.challenge_type, SCEPChallengeType.OKTA_CA.name)
        self.assertEqual(
            scep_config.get_challenge_kwargs(),
            {"url": "https://www.example.com/ndes/",
             "username": "YoLo",
             "password": "FoMo"}
        )

    # update

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_scep_config_static_ca_challenge_exception(self, logger_exception):
        scep_config = force_scep_config(provisioning_uid="yolo")
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "STATIC",
                    # missing static_challenge_kwargs
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            SCEPConfig, "yolo"
        )
        scep_config.refresh_from_db()
        self.assertNotEqual(scep_config.name, "Name")

    def test_update_scep_config_static_ca_challenge(self):
        scep_config = force_scep_config(provisioning_uid="yolo")
        qs = SCEPConfig.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(scep_config.get_challenge_kwargs()["challenge"], "FoMo")
        SCEPConfigProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "url": "https://www.example.com/scep/",
                    "challenge_type": "STATIC",
                    "static_challenge_kwargs": {
                        "challenge": "FoMo",
                    }
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), scep_config)
        scep_config = qs.first()
        self.assertEqual(scep_config.provisioning_uid, "yolo")
        self.assertEqual(scep_config.challenge_type, SCEPChallengeType.STATIC.name)
        self.assertEqual(scep_config.get_challenge_kwargs(), {"challenge": "FoMo"})
