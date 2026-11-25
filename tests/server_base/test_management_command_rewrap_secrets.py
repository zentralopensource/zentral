from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from unittest.mock import patch
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import models
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.jamf.models import JamfInstance
from zentral.core.secret_engines import secret_engines


class RewrapSecretsManagementCommandTestCase(TestCase):
    def setUp(self):
        super().setUp()
        secret_engines.load_config({})
        self.addCleanup(secret_engines.load_config, {})

    def _force_jamf_instance(self):
        jamf_instance = JamfInstance.objects.create(
            host="{}.example.com".format(get_random_string(12)),
            port=443,
            path="/JSSResource",
            user=get_random_string(12)
        )
        jamf_instance.set_password(get_random_string(12))
        super(JamfInstance, jamf_instance).save()
        jamf_instance.refresh_from_db()
        return jamf_instance

    def _load_fernet_engine(self):
        secret_engines.load_config({
            "fernet": {"backend": "zentral.core.secret_engines.backends.fernet",
                       "passwords": ["undeuxtrois"]}
        })

    def _call_command(self, *args):
        stdout = StringIO()
        original_save = models.Model.save
        with (patch.object(models.Model, "save", autospec=True, side_effect=original_save) as save,
              redirect_stdout(stdout),
              redirect_stderr(StringIO())):
            call_command("rewrap_secrets", *args)
        return stdout.getvalue(), save

    def _jamf_instance_save_calls(self, save, jamf_instance):
        return [c for c in save.call_args_list
                if isinstance(c.args[0], JamfInstance) and c.args[0].pk == jamf_instance.pk]

    def test_rewrap_secrets_saves_only_the_rewrapped_fields(self):
        jamf_instance = self._force_jamf_instance()
        password = jamf_instance.get_password()
        self._load_fernet_engine()
        stdout, save = self._call_command()
        self.assertIn("JamfInstance: 1 objects to update", stdout)
        save_calls = self._jamf_instance_save_calls(save, jamf_instance)
        self.assertEqual(len(save_calls), 1)
        self.assertEqual(save_calls[0].kwargs, {"update_fields": ["password"]})
        updated_jamf_instance = JamfInstance.objects.get(pk=jamf_instance.pk)
        self.assertEqual(updated_jamf_instance.password.split("$")[0], "fernet")
        self.assertEqual(updated_jamf_instance.get_password(), password)
        self.assertEqual(updated_jamf_instance.updated_at, jamf_instance.updated_at)
        self.assertEqual(updated_jamf_instance.version, jamf_instance.version)

    def test_rewrap_secrets_saves_a_value_changed_in_place(self):
        jamf_instance = self._force_jamf_instance()

        def rewrap_secrets(obj):
            obj.inventory_extension_attributes.append("yolo")

        with patch.object(JamfInstance, "rewrap_secrets", autospec=True, side_effect=rewrap_secrets):
            _, save = self._call_command()
        save_calls = self._jamf_instance_save_calls(save, jamf_instance)
        self.assertEqual(len(save_calls), 1)
        self.assertEqual(save_calls[0].kwargs, {"update_fields": ["inventory_extension_attributes"]})
        self.assertEqual(JamfInstance.objects.get(pk=jamf_instance.pk).inventory_extension_attributes, ["yolo"])

    def test_rewrap_secrets_does_not_save_unchanged_objects(self):
        jamf_instance = self._force_jamf_instance()
        stdout, save = self._call_command()
        self.assertIn("JamfInstance: 1 objects to update", stdout)
        self.assertEqual(self._jamf_instance_save_calls(save, jamf_instance), [])
        updated_jamf_instance = JamfInstance.objects.get(pk=jamf_instance.pk)
        self.assertEqual(updated_jamf_instance.password, jamf_instance.password)
        self.assertEqual(updated_jamf_instance.updated_at, jamf_instance.updated_at)

    def test_rewrap_secrets_queryset(self):
        jamf_instance = self._force_jamf_instance()
        skipped_jamf_instance = self._force_jamf_instance()
        self._load_fernet_engine()
        with patch.object(JamfInstance, "rewrap_secrets_queryset", create=True,
                          return_value=JamfInstance.objects.filter(pk=jamf_instance.pk)):
            stdout, save = self._call_command()
        self.assertIn("JamfInstance: 1 objects to update", stdout)
        self.assertEqual(len(self._jamf_instance_save_calls(save, jamf_instance)), 1)
        self.assertEqual(self._jamf_instance_save_calls(save, skipped_jamf_instance), [])
        self.assertEqual(JamfInstance.objects.get(pk=jamf_instance.pk).password.split("$")[0], "fernet")
        self.assertEqual(
            JamfInstance.objects.get(pk=skipped_jamf_instance.pk).password,
            skipped_jamf_instance.password
        )

    def test_rewrap_secrets_keeps_the_saved_objects_after_an_error(self):
        jamf_instance = self._force_jamf_instance()
        failing_jamf_instance = self._force_jamf_instance()
        self._load_fernet_engine()
        original_rewrap_secrets = JamfInstance.rewrap_secrets

        def rewrap_secrets(obj):
            if obj.pk == failing_jamf_instance.pk:
                raise ValueError("yolo")
            original_rewrap_secrets(obj)

        with (patch.object(JamfInstance, "rewrap_secrets_queryset", create=True,
                           return_value=JamfInstance.objects.filter(
                               pk__in=[jamf_instance.pk, failing_jamf_instance.pk]
                           ).order_by("pk")),
              patch.object(JamfInstance, "rewrap_secrets", autospec=True, side_effect=rewrap_secrets),
              self.assertRaises(ValueError)):
            self._call_command()
        self.assertEqual(JamfInstance.objects.get(pk=jamf_instance.pk).password.split("$")[0], "fernet")
        self.assertEqual(
            JamfInstance.objects.get(pk=failing_jamf_instance.pk).password,
            failing_jamf_instance.password
        )

    def test_rewrap_secrets_stops_at_a_decryption_error(self):
        jamf_instance = self._force_jamf_instance()
        failing_jamf_instance = self._force_jamf_instance()
        JamfInstance.objects.filter(pk=failing_jamf_instance.pk).update(password="yolo$fomo")
        next_jamf_instance = self._force_jamf_instance()
        self._load_fernet_engine()
        with (patch.object(JamfInstance, "rewrap_secrets_queryset", create=True,
                           return_value=JamfInstance.objects.filter(
                               pk__in=[jamf_instance.pk, failing_jamf_instance.pk, next_jamf_instance.pk]
                           ).order_by("pk")),
              self.assertRaisesMessage(
                  CommandError, f"Could not rewrap the secrets of jamf.JamfInstance {failing_jamf_instance.pk}"
              )):
            self._call_command()
        self.assertEqual(JamfInstance.objects.get(pk=jamf_instance.pk).password.split("$")[0], "fernet")
        self.assertEqual(JamfInstance.objects.get(pk=failing_jamf_instance.pk).password, "yolo$fomo")
        self.assertEqual(JamfInstance.objects.get(pk=next_jamf_instance.pk).password, next_jamf_instance.password)

    def _call_command_with_change_after_listing(self, jamf_instance, change):
        jamf_instance_pk = jamf_instance.pk

        def list_then_change(iterable, total):
            items = list(iterable)
            if [getattr(item, "pk", item) for item in items] == [jamf_instance_pk]:
                change()
            return items

        with (patch.object(JamfInstance, "rewrap_secrets_queryset", create=True,
                           return_value=JamfInstance.objects.filter(pk=jamf_instance.pk)),
              patch("base.management.commands.rewrap_secrets.tqdm", side_effect=list_then_change)):
            return self._call_command()

    def test_rewrap_secrets_skips_an_object_deleted_after_listing(self):
        jamf_instance = self._force_jamf_instance()
        self._load_fernet_engine()
        _, save = self._call_command_with_change_after_listing(jamf_instance, jamf_instance.delete)
        self.assertEqual([c for c in save.call_args_list if isinstance(c.args[0], JamfInstance)], [])
        self.assertFalse(JamfInstance.objects.filter(pk=jamf_instance.pk).exists())

    def test_rewrap_secrets_keeps_a_value_saved_after_listing(self):
        jamf_instance = self._force_jamf_instance()
        new_password = get_random_string(12)
        self._load_fernet_engine()

        def update_password():
            obj = JamfInstance.objects.get(pk=jamf_instance.pk)
            obj.set_password(new_password)
            super(JamfInstance, obj).save()

        self._call_command_with_change_after_listing(jamf_instance, update_password)
        updated_jamf_instance = JamfInstance.objects.get(pk=jamf_instance.pk)
        self.assertEqual(updated_jamf_instance.password.split("$")[0], "fernet")
        self.assertEqual(updated_jamf_instance.get_password(), new_password)

    def test_rewrap_secrets_dry_run(self):
        jamf_instance = self._force_jamf_instance()
        self._load_fernet_engine()
        stdout, save = self._call_command("--dry-run")
        self.assertIn("JamfInstance: 1 objects to update", stdout)
        self.assertEqual(self._jamf_instance_save_calls(save, jamf_instance), [])
        updated_jamf_instance = JamfInstance.objects.get(pk=jamf_instance.pk)
        self.assertEqual(updated_jamf_instance.password, jamf_instance.password)
