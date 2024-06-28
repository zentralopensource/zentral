from unittest.mock import patch
from cryptography.hazmat.primitives import serialization
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.mdm.models import PushCertificate
from zentral.contrib.mdm.provisioning import PushCertificateProvisioner
from zentral.utils.ssl import ensure_bytes
from .utils import force_push_certificate, force_push_certificate_material


class MDMPushCertificateProvisioningTestCase(TestCase):
    @property
    def app_config(self):
        return apps.get_app_config("mdm")

    @staticmethod
    def fake_app_settings(**uid_spec_d):
        return {
            "apps": {
                "zentral.contrib.mdm": {
                    "provisioning": {
                        "push_certificates": uid_spec_d
                    }
                }
            }
        }

    # model

    def test_provisioner_model(self):
        self.assertEqual(PushCertificateProvisioner(self.app_config, {}).model, PushCertificate)

    def test_unknown_push_certificate(self):
        force_push_certificate()
        self.assertIsNone(PushCertificateProvisioner(self.app_config, {}).get_instance_by_uid("yolo"))

    def test_existing_push_certificate(self):
        uid = get_random_string(12)
        push_certificate = force_push_certificate(provisioning_uid=uid)
        self.assertEqual(
            PushCertificateProvisioner(self.app_config, {}).get_instance_by_uid(uid),
            push_certificate,
        )

    # can_be_deleted

    def test_can_be_deleted(self):
        push_certificate = force_push_certificate()
        self.assertTrue(push_certificate.can_be_deleted())

    def test_provisioned_cannot_be_deleted(self):
        push_certificate = force_push_certificate(provisioning_uid="YoLoFoMo")
        self.assertFalse(push_certificate.can_be_deleted())

    # can_be_updated

    def test_can_be_updated(self):
        push_certificate = force_push_certificate()
        self.assertTrue(push_certificate.can_be_updated())

    def test_provisioned_cannot_be_updated(self):
        push_certificate = force_push_certificate(provisioning_uid="YoLoFoMo")
        self.assertFalse(push_certificate.can_be_updated())

    # serializer

    def test_serializer_full_serialization(self):
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="YoLoFoMo")
        serializer = PushCertificateProvisioner.serializer_class(push_certificate)
        self.assertEqual(
            serializer.data,
            {'id': push_certificate.pk,
             'provisioning_uid': "YoLoFoMo",
             'name': push_certificate.name,
             'topic': push_certificate.topic,
             'not_before': push_certificate.not_before.isoformat().split("+")[0],
             'not_after': push_certificate.not_after.isoformat().split("+")[0],
             'certificate': push_certificate.certificate.decode("ascii"),
             'created_at': push_certificate.created_at.isoformat(),
             'updated_at': push_certificate.updated_at.isoformat()}
        )

    def test_serializer_reduced_serialization(self):
        push_certificate = force_push_certificate()
        push_certificate.certificate = push_certificate.not_after = push_certificate.not_before = None
        push_certificate.topic = None
        push_certificate.save()
        serializer = PushCertificateProvisioner.serializer_class(push_certificate)
        self.assertEqual(
            serializer.data,
            {'id': push_certificate.pk,
             'provisioning_uid': None,
             'name': push_certificate.name,
             'topic': None,
             'not_before': None,
             'not_after': None,
             'certificate': None,
             'created_at': push_certificate.created_at.isoformat(),
             'updated_at': push_certificate.updated_at.isoformat()}
        )

    def test_serializer_required_fields(self):
        serializer = PushCertificateProvisioner.serializer_class(data={})
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'name': ['This field is required.']}
        )

    # settings

    def test_no_app_settings(self):
        self.assertEqual(PushCertificateProvisioner(self.app_config, {}).app_settings, {})

    def test_app_settings(self):
        self.assertEqual(
            PushCertificateProvisioner(
                self.app_config,
                {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}}
            ).app_settings,
            {"yolo": "fomo"},
        )

    def test_no_app_settings_no_uid_spec(self):
        self.assertEqual(list(PushCertificateProvisioner(self.app_config, {}).iter_uid_spec()), [])

    def test_app_settings_no_provisioning_no_uid_spec(self):
        self.assertEqual(
            list(
                PushCertificateProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"yolo": "fomo"}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_no_config_key_no_uid_spec(self):
        self.assertEqual(
            list(
                PushCertificateProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"provisioning": {"yolo": {}}}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_uid_spec(self):
        self.assertEqual(
            list(
                PushCertificateProvisioner(
                    self.app_config,
                    self.fake_app_settings(yolo={"un": 1}, fomo={"deux": 2})
                ).iter_uid_spec()
            ),
            [("yolo", {"un": 1}), ("fomo", {"deux": 2})]
        )

    # create

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_push_certificate_missing_name_exception(self, logger_exception):
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    # missing name
                }
            )
        ).apply()
        self.assertEqual(PushCertificate.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            PushCertificate, "yolo"
        )

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_push_certificate_certificate_exception(self, logger_exception):
        cert_pem, _, _ = force_push_certificate_material()
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "certificate": cert_pem,
                }
            )
        ).apply()
        self.assertEqual(PushCertificate.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            PushCertificate, "yolo"
        )

    def test_create_push_certificate(self):
        qs = PushCertificate.objects.all()
        self.assertEqual(qs.count(), 0)
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        push_certificate = qs.first()
        self.assertEqual(push_certificate.provisioning_uid, "yolo")
        self.assertEqual(push_certificate.name, "Name")
        key = serialization.load_pem_private_key(push_certificate.get_private_key(), None)
        self.assertEqual(key.key_size, 2048)

    # update

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_push_certificate_no_name_no_update(self, logger_exception):
        push_certificate = force_push_certificate(provisioning_uid="yolo")
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    # missing name
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            PushCertificate, "yolo"
        )
        push_certificate.refresh_from_db()
        self.assertNotEqual(push_certificate.name, "Name")

    def test_update_push_certificate_update_no_certificate_change(self):
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="yolo")
        cert_bytes = ensure_bytes(push_certificate.certificate)
        self.assertTrue(len(cert_bytes) > 0)
        privkey_bytes = push_certificate.get_private_key()
        qs = PushCertificate.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(push_certificate.name, "Name")
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    # no certificate, we keep the one we have
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), push_certificate)
        push_certificate = qs.first()
        self.assertEqual(push_certificate.provisioning_uid, "yolo")
        self.assertEqual(push_certificate.name, "Name")
        self.assertEqual(ensure_bytes(push_certificate.certificate), cert_bytes)
        self.assertEqual(push_certificate.get_private_key(), privkey_bytes)

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_push_certificate_certificate_no_match_no_change(self, logger_exception):
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="yolo")
        cert_pem, _, _ = force_push_certificate_material(topic=push_certificate.topic)
        cert_bytes = ensure_bytes(push_certificate.certificate)
        self.assertTrue(len(cert_bytes) > 0)
        privkey_bytes = push_certificate.get_private_key()
        qs = PushCertificate.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(push_certificate.name, "Name")
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "certificate": cert_pem,  # not a match for the private key
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            PushCertificate, "yolo"
        )
        push_certificate.refresh_from_db()
        self.assertNotEqual(push_certificate.name, "Name")
        self.assertEqual(ensure_bytes(push_certificate.certificate), cert_bytes)
        self.assertEqual(push_certificate.get_private_key(), privkey_bytes)

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_push_certificate_certificate_different_topic_no_change(self, logger_exception):
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="yolo")
        cert_pem, _, _ = force_push_certificate_material(privkey_bytes=push_certificate.get_private_key())
        cert_bytes = ensure_bytes(push_certificate.certificate)
        self.assertTrue(len(cert_bytes) > 0)
        privkey_bytes = push_certificate.get_private_key()
        qs = PushCertificate.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(push_certificate.name, "Name")
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "certificate": cert_pem,  # different topic
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            PushCertificate, "yolo"
        )
        push_certificate.refresh_from_db()
        self.assertNotEqual(push_certificate.name, "Name")
        self.assertEqual(ensure_bytes(push_certificate.certificate), cert_bytes)
        self.assertEqual(push_certificate.get_private_key(), privkey_bytes)

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_push_certificate_conflict_on_topic_no_change(self, logger_exception):
        push_certificate_conflict = force_push_certificate()
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="yolo")
        push_certificate.certificate = None  # remove the cert
        push_certificate.topic = None  # remove the topic
        push_certificate.save()
        cert_pem, _, _ = force_push_certificate_material(
            push_certificate_conflict.topic,
            privkey_bytes=push_certificate.get_private_key()
        )
        privkey_bytes = push_certificate.get_private_key()
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "certificate": cert_pem,  # different topic
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            PushCertificate, "yolo"
        )
        push_certificate.refresh_from_db()
        self.assertNotEqual(push_certificate.name, "Name")
        self.assertIsNone(push_certificate.certificate)
        self.assertEqual(push_certificate.get_private_key(), privkey_bytes)

    def test_update_push_certificate_update(self):
        push_certificate = force_push_certificate(with_material=True, provisioning_uid="yolo")
        cert_pem, _, _ = force_push_certificate_material(
            topic=push_certificate.topic,
            privkey_bytes=push_certificate.get_private_key()
        )
        cert_bytes = ensure_bytes(push_certificate.certificate)
        self.assertTrue(len(cert_bytes) > 0)
        privkey_bytes = push_certificate.get_private_key()
        qs = PushCertificate.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(push_certificate.name, "Name")
        PushCertificateProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Name",
                    "certificate": cert_pem,  # same topic, match for the privkey
                }
            )
        ).apply()
        push_certificate.refresh_from_db()
        self.assertEqual(push_certificate.name, "Name")
        self.assertEqual(ensure_bytes(push_certificate.certificate), cert_pem)
        self.assertEqual(push_certificate.get_private_key(), privkey_bytes)
