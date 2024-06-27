import plistlib
from unittest.mock import Mock, patch
from django.apps import apps
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.monolith.models import Repository
from zentral.contrib.monolith.provisioning import RepositoryProvisioner
from zentral.core.events.base import AuditEvent
from .utils import force_repository


class MonolithRepositoryProvisioningTestCase(TestCase):
    @property
    def app_config(self):
        return apps.get_app_config("monolith")

    @staticmethod
    def fake_app_settings(**uid_spec_d):
        return {
            "apps": {
                "zentral.contrib.monolith": {
                    "provisioning": {
                        "repositories": uid_spec_d
                    }
                }
            }
        }

    # model

    def test_provisioner_model(self):
        self.assertEqual(RepositoryProvisioner(self.app_config, {}).model, Repository)

    def test_unknown_repository(self):
        force_repository()
        self.assertIsNone(RepositoryProvisioner(self.app_config, {}).get_instance_by_uid("yolo"))

    def test_existing_repository(self):
        uid = get_random_string(12)
        repository = force_repository(provisioning_uid=uid)
        self.assertEqual(
            RepositoryProvisioner(self.app_config, {}).get_instance_by_uid(uid),
            repository,
        )

    # serializer

    def test_serializer_required_fields(self):
        serializer = RepositoryProvisioner.serializer_class(data={})
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'name': ['This field is required.'],
             'backend': ['This field is required.']}
        )

    def test_serializer_unknown_backend(self):
        serializer = RepositoryProvisioner.serializer_class(data={
            "name": "yolo",
            "backend": "YOLO",
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'backend': ['"YOLO" is not a valid choice.']}
        )

    def test_serializer_required_s3_backend_fields(self):
        serializer = RepositoryProvisioner.serializer_class(data={
            "name": "yolo",
            "backend": "S3",
            "s3_kwargs": {},
        })
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'s3_kwargs': {'bucket': ['This field is required.']}}
        )

    # settings

    def test_no_app_settings(self):
        self.assertEqual(RepositoryProvisioner(self.app_config, {}).app_settings, {})

    def test_app_settings(self):
        self.assertEqual(
            RepositoryProvisioner(
                self.app_config,
                {"apps": {"zentral.contrib.monolith": {"yolo": "fomo"}}}
            ).app_settings,
            {"yolo": "fomo"},
        )

    def test_no_app_settings_no_uid_spec(self):
        self.assertEqual(list(RepositoryProvisioner(self.app_config, {}).iter_uid_spec()), [])

    def test_app_settings_no_provisioning_no_uid_spec(self):
        self.assertEqual(
            list(
                RepositoryProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.monolith": {"yolo": "fomo"}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_no_config_key_no_uid_spec(self):
        self.assertEqual(
            list(
                RepositoryProvisioner(
                    self.app_config,
                    {"apps": {"zentral.contrib.mdm": {"provisioning": {"yolo": {}}}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_uid_spec(self):
        self.assertEqual(
            list(
                RepositoryProvisioner(
                    self.app_config,
                    self.fake_app_settings(yolo={"un": 1}, fomo={"deux": 2})
                ).iter_uid_spec()
            ),
            [("yolo", {"un": 1}), ("fomo", {"deux": 2})]
        )

    # create

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_s3_repository_exception(self, logger_exception):
        RepositoryProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "HaHa",
                    "backend": "S3",
                    # missing s3_kwargs
                }
            )
        ).apply()
        self.assertEqual(Repository.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            Repository, "yolo"
        )

    @patch("zentral.contrib.monolith.provisioning.logger.error")
    @patch("zentral.contrib.monolith.provisioning.load_repository_backend")
    @patch("zentral.contrib.monolith.provisioning.notifier.send_notification")
    def test_create_s3_repository_sync_error(self, send_notification, load_repository_backend, logger_error):
        mocked_repository = Mock()
        mocked_repository.sync_catalogs.side_effect = ValueError("YOLO")
        load_repository_backend.return_value = mocked_repository
        qs = Repository.objects.all()
        self.assertEqual(qs.count(), 0)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            RepositoryProvisioner(
                self.app_config,
                self.fake_app_settings(
                    yolo={
                        "name": "Haha",
                        "backend": "S3",
                        "s3_kwargs": {
                          "bucket": "willie-nick-heather",
                        }
                    }
                )
            ).apply()
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(qs.count(), 1)
        repository = qs.first()
        self.assertEqual(repository.provisioning_uid, "yolo")
        self.assertEqual(repository.backend, "S3")
        self.assertEqual(
            repository.get_backend_kwargs(),
            {'bucket': 'willie-nick-heather'},
        )
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
        logger_error.assert_called_once_with("Could not sync provisioned repository %s", "yolo")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    @patch("zentral.contrib.monolith.provisioning.notifier.send_notification")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_all_catalog_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.get_icon_hashes_content")
    @patch("zentral.contrib.monolith.repository_backends.s3.S3Repository.iter_client_resources")
    def test_create_s3_repository(
        self,
        iter_client_resources,
        get_icon_hashes_content,
        get_all_catalog_content,
        send_notification,
        post_event
    ):
        iter_client_resources.return_value = ["site_default.zip",]
        get_icon_hashes_content.return_value = plistlib.dumps({
            "yolo.png": "a" * 64
        })
        get_all_catalog_content.return_value = plistlib.dumps([
            {"catalogs": ["production"],
             "name": "yolo",
             "version": "1.0"}
        ])
        qs = Repository.objects.all()
        self.assertEqual(qs.count(), 0)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            RepositoryProvisioner(
                self.app_config,
                self.fake_app_settings(
                    yolo={
                        "name": "Haha",
                        "backend": "S3",
                        "s3_kwargs": {
                          "bucket": "willie-nick-heather",
                          "region_name": "eu-central-1",
                          "access_key_id": "cehRSFhRvCevQY5L",
                          "secret_access_key": "cehRSFhRvCevQY5L",
                          "endpoint_url": "https://www.example.com/"
                        }
                    }
                )
            ).apply()
        self.assertEqual(len(callbacks), 2)
        self.assertEqual(qs.count(), 1)
        repository = qs.first()
        self.assertEqual(repository.provisioning_uid, "yolo")
        self.assertEqual(repository.backend, "S3")
        self.assertEqual(
            repository.get_backend_kwargs(),
            {'access_key_id': 'cehRSFhRvCevQY5L',
             'bucket': 'willie-nick-heather',
             'endpoint_url': 'https://www.example.com/',
             'region_name': 'eu-central-1',
             'secret_access_key': 'cehRSFhRvCevQY5L'}
        )
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
        self.assertEqual(len(post_event.call_args_list), 3)
        self.assertTrue(all(isinstance(c.args[0], AuditEvent) for c in post_event.call_args_list))

    # update

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_s3_repository_exception(self, logger_exception):
        repository = force_repository(provisioning_uid="yolo")
        RepositoryProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "HaHa",
                    # unknown backend
                    "backend": "Q1",
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            Repository, "yolo"
        )
        repository.refresh_from_db()
        self.assertNotEqual(repository.name, "HaHa")

    @patch("zentral.contrib.monolith.provisioning.notifier.send_notification")
    def test_update_s3_repository(self, send_notification):
        repository = force_repository(provisioning_uid="yolo")
        qs = Repository.objects.all()
        self.assertEqual(qs.count(), 1)
        self.assertNotEqual(
            repository.get_backend_kwargs()["access_key_id"],
            "cehRSFhRvCevQY5L"
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            RepositoryProvisioner(
                self.app_config,
                self.fake_app_settings(
                    yolo={
                        "name": "HaHa",
                        "backend": "S3",
                        "s3_kwargs": {
                          "bucket": "willie-nick-heather",
                          "region_name": "eu-central-1",
                          "access_key_id": "cehRSFhRvCevQY5L",
                          "secret_access_key": "cehRSFhRvCevQY5L",
                          "endpoint_url": "https://www.example.com/"
                        }
                    }
                )
            ).apply()
        self.assertEqual(len(callbacks), 1)
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), repository)
        repository = qs.first()
        self.assertEqual(repository.provisioning_uid, "yolo")
        self.assertEqual(repository.backend, "S3")
        self.assertEqual(
            repository.get_backend_kwargs(),
            {'access_key_id': 'cehRSFhRvCevQY5L',
             'bucket': 'willie-nick-heather',
             'endpoint_url': 'https://www.example.com/',
             'region_name': 'eu-central-1',
             'secret_access_key': 'cehRSFhRvCevQY5L'}
        )
        send_notification.assert_called_once_with("monolith.repository", str(repository.pk))
