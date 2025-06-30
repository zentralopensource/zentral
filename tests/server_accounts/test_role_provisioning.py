from unittest.mock import patch
from django.apps import apps
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.utils.crypto import get_random_string
from accounts.models import Group
from accounts.provisioning import RoleProvisioner
from .utils import force_role


class MonolithRoleProvisioningTestCase(TestCase):
    @property
    def app_config(self):
        return apps.get_app_config("accounts")

    @staticmethod
    def fake_app_settings(**uid_spec_d):
        return {
            "apps": {
                "accounts": {
                    "provisioning": {
                        "roles": uid_spec_d
                    }
                }
            }
        }

    # model

    def test_provisioner_model(self):
        self.assertEqual(RoleProvisioner(self.app_config, {}).model, Group)

    def test_unknown_role(self):
        force_role()
        self.assertIsNone(RoleProvisioner(self.app_config, {}).get_instance_by_uid("yolo"))

    def test_existing_role(self):
        uid = get_random_string(12)
        role = force_role(provisioning_uid=uid)
        self.assertEqual(
            RoleProvisioner(self.app_config, {}).get_instance_by_uid(uid),
            role,
        )

    # serializer

    def test_serializer_required_fields(self):
        serializer = RoleProvisioner.serializer_class(data={})
        serializer.is_valid()
        self.assertEqual(
            serializer.errors,
            {'name': ['This field is required.']}
        )

    # settings

    def test_no_app_settings(self):
        self.assertEqual(RoleProvisioner(self.app_config, {}).app_settings, {})

    def test_app_settings(self):
        self.assertEqual(
            RoleProvisioner(
                self.app_config,
                {"apps": {"accounts": {"yolo": "fomo"}}}
            ).app_settings,
            {"yolo": "fomo"},
        )

    def test_no_app_settings_no_uid_spec(self):
        self.assertEqual(list(RoleProvisioner(self.app_config, {}).iter_uid_spec()), [])

    def test_app_settings_no_provisioning_no_uid_spec(self):
        self.assertEqual(
            list(
                RoleProvisioner(
                    self.app_config,
                    {"apps": {"accounts": {"yolo": "fomo"}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_no_config_key_no_uid_spec(self):
        self.assertEqual(
            list(
                RoleProvisioner(
                    self.app_config,
                    {"apps": {"accounts": {"provisioning": {"yolo": {}}}}},
                ).iter_uid_spec()
            ),
            []
        )

    def test_app_settings_provisioning_uid_spec(self):
        self.assertEqual(
            list(
                RoleProvisioner(
                    self.app_config,
                    self.fake_app_settings(yolo={"un": 1}, fomo={"deux": 2})
                ).iter_uid_spec()
            ),
            [("yolo", {"un": 1}), ("fomo", {"deux": 2})]
        )

    # create

    @patch("zentral.utils.provisioning.logger.exception")
    def test_create_role_exception(self, logger_exception):
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "nam": "HaHa",
                }
            )
        ).apply()
        self.assertEqual(Group.objects.count(), 0)
        logger_exception.assert_called_once_with(
            "Could not create %s instance %s",
            Group, "yolo"
        )

    def test_create_role_no_perms(self):
        qs = Group.objects.all()
        self.assertEqual(qs.count(), 0)
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Haha",
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        role = qs.first()
        self.assertEqual(role.provisioned_role.provisioning_uid, "yolo")
        self.assertEqual(role.name, "Haha")
        self.assertEqual(role.permissions.count(), 0)

    def test_create_role_empty_perms(self):
        qs = Group.objects.all()
        self.assertEqual(qs.count(), 0)
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Haha",
                    "permissions": [],
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        role = qs.first()
        self.assertEqual(role.provisioned_role.provisioning_uid, "yolo")
        self.assertEqual(role.name, "Haha")
        self.assertEqual(role.permissions.count(), 0)

    def test_create_role(self):
        qs = Group.objects.all()
        self.assertEqual(qs.count(), 0)
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "Haha",
                    "permissions": [
                        "monolith.view_repository",
                        "not_a_real_perm",  # will be ignored
                    ],
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        role = qs.first()
        self.assertEqual(role.provisioned_role.provisioning_uid, "yolo")
        self.assertEqual(role.name, "Haha")
        role_perms_qs = role.permissions.all()
        self.assertEqual(role_perms_qs.count(), 1)
        role_perm = role_perms_qs.first()
        self.assertEqual(role_perm.content_type.app_label, "monolith")
        self.assertEqual(role_perm.codename, "view_repository")

    # update

    @patch("zentral.utils.provisioning.logger.exception")
    def test_update_role_exception(self, logger_exception):
        role = force_role(provisioning_uid="yolo")
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "nam": "HaHa",
                }
            )
        ).apply()
        logger_exception.assert_called_once_with(
            "Could not update %s instance %s",
            Group, "yolo"
        )
        role.refresh_from_db()
        self.assertNotEqual(role.name, "HaHa")

    def test_update_role_add_perm(self):
        role = force_role(provisioning_uid="yolo")
        self.assertEqual(role.permissions.count(), 0)
        qs = Group.objects.all()
        self.assertEqual(qs.count(), 1)
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "HaHa",
                    "permissions": ["osquery.change_query"],
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), role)
        role.refresh_from_db()
        self.assertEqual(role.provisioned_role.provisioning_uid, "yolo")
        self.assertEqual(role.name, "HaHa")
        role_perms_qs = role.permissions.all()
        self.assertEqual(role_perms_qs.count(), 1)
        role_perm = role_perms_qs.first()
        self.assertEqual(role_perm.content_type.app_label, "osquery")
        self.assertEqual(role_perm.codename, "change_query")

    def test_update_role_remove_perm(self):
        role = force_role(provisioning_uid="yolo")
        role.permissions.add(Permission.objects.get(content_type__app_label="osquery", codename="change_query"))
        self.assertEqual(role.permissions.count(), 1)
        qs = Group.objects.all()
        self.assertEqual(qs.count(), 1)
        RoleProvisioner(
            self.app_config,
            self.fake_app_settings(
                yolo={
                    "name": "HaHa",
                }
            )
        ).apply()
        self.assertEqual(qs.count(), 1)
        self.assertEqual(qs.first(), role)
        role.refresh_from_db()
        self.assertEqual(role.provisioned_role.provisioning_uid, "yolo")
        self.assertEqual(role.name, "HaHa")
        self.assertEqual(role.permissions.count(), 0)
