from functools import reduce
import io
import json
import operator
import zipfile
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase
from unittest.mock import patch
from zentral.contrib.inventory.models import MetaBusinessUnit, Tag
from zentral.contrib.munki.models import Enrollment
from accounts.models import User
from zentral.core.events.base import AuditEvent
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision
from .utils import force_configuration, force_enrollment, force_script_check, make_enrolled_machine


class MunkiSetupViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)
        # mbu
        cls.mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.mbu.create_enrollment_business_unit()

    # utility methods

    def _login_redirect(self, url):
        response = self.client.get(url)
        self.assertRedirects(response, "{u}?next={n}".format(u=reverse("login"), n=url))

    def _login(self, *permissions):
        if permissions:
            permission_filter = reduce(operator.or_, (
                Q(content_type__app_label=app_label, codename=codename)
                for app_label, codename in (
                    permission.split(".")
                    for permission in permissions
                )
            ))
            self.group.permissions.set(list(Permission.objects.filter(permission_filter)))
        else:
            self.group.permissions.clear()
        self.client.force_login(self.user)

    def _post_as_json(self, url_name, data):
        return self.client.post(reverse("munki:{}".format(url_name)),
                                json.dumps(data),
                                content_type="application/json")

    # index

    def test_index_redirect(self):
        self._login_redirect(reverse("munki:index"))

    def test_index_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_configurations(self):
        self._login("munki.view_configuration")
        response = self.client.get(reverse("munki:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("munki:configurations"))
        self.assertNotContains(response, reverse("munki:script_checks"))

    def test_index_script_checks(self):
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("munki:configurations"))
        self.assertContains(response, reverse("munki:script_checks"))

    # configurations

    def test_configurations_redirect(self):
        self._login_redirect(reverse("munki:configurations"))

    def test_configurations_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_configurations(self):
        self._login("munki.view_configuration")
        response = self.client.get(reverse("munki:configurations"))
        self.assertEqual(response.status_code, 200)

    def test_configuration_enrollment_and_machine_count(self):
        self._login("munki.view_configuration")
        configuration = force_configuration()
        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)

        enrollment = force_enrollment(configuration=configuration, meta_business_unit=self.mbu)
        make_enrolled_machine(enrollment)
        make_enrolled_machine(enrollment)

        response = self.client.get(reverse("munki:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['object_list']), 1)
        self.assertEqual(response.context['object_list'][0].enrollment__count, 2)
        self.assertEqual(response.context['object_list'][0].enrollment__enrolledmachine__count, 3)

    def test_configuration_without_event_links(self):
        configuration = force_configuration()
        self._login("munki.view_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        self.assertNotContains(response, reverse("munki:configuration_events",
                                                 args=(configuration.pk,)))

    def test_configuration_with_event_links(self):
        configuration = force_configuration()
        self._login("munki.view_configuration",
                    "munki.view_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        self.assertContains(response, reverse("munki:configuration_events",
                                              args=(configuration.pk,)))

    def test_configuration_events_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("munki:configuration_events", args=(configuration.pk,)))

    def test_configuration_events_permission_denied(self):
        configuration = force_configuration()
        self._login("munki.view_configuration")
        response = self.client.get(reverse("munki:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.get_aggregated_object_event_counts")
    def test_configuration_events_ok(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        configuration = force_configuration()
        self._login("munki.view_configuration",
                    "munki.view_enrollment")
        response = self.client.get(reverse("munki:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_events.html")

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_object_events")
    def test_fetch_configuration_events_ok(self, fetch_object_events):
        fetch_object_events.return_value = {}
        configuration = force_configuration()
        self._login("munki.view_configuration",
                    "munki.view_enrollment")
        response = self.client.get(reverse("munki:configuration_events", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_events.html")

    # create configuration

    def test_create_configuration_redirect(self):
        self._login_redirect(reverse("munki:create_configuration"))

    def test_create_configuration_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:create_configuration"))
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_get(self):
        self._login("munki.add_configuration")
        response = self.client.get(reverse("munki:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_configuration_post(self, post_event):
        self._login("munki.add_configuration", "munki.view_configuration")
        name = get_random_string(12)
        description = get_random_string(12)
        collected_condition_keys = sorted(get_random_string(12) for _ in range(3))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("munki:create_configuration"),
                                        {"name": name,
                                         "description": description,
                                         "inventory_apps_full_info_shard": 17,
                                         "principal_user_detection_sources": "logged_in_user",
                                         "principal_user_detection_domains": "yolo.fr",
                                         "collected_condition_keys": " ,  ".join(collected_condition_keys),
                                         "managed_installs_sync_interval_days": 1,
                                         "script_checks_run_interval_seconds": 7231,
                                         "auto_reinstall_incidents": "on"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        self.assertContains(response, name)
        self.assertContains(response, description)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, name)
        self.assertEqual(configuration.description, description)
        self.assertTrue(configuration.auto_reinstall_incidents)
        self.assertFalse(configuration.auto_failed_install_incidents)
        self.assertEqual(configuration.managed_installs_sync_interval_days, 1)
        self.assertEqual(configuration.script_checks_run_interval_seconds, 7231)
        self.assertEqual(sorted(configuration.collected_condition_keys), collected_condition_keys)
        for condition_key in collected_condition_keys:
            self.assertContains(response, condition_key)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                "action": "created",
                "object":
                {
                 "model": "munki.configuration",
                 "pk": str(configuration.pk),
                 "new_value": {
                     "pk": configuration.pk,
                     "name": name,
                     "description": description,
                     "inventory_apps_full_info_shard": 17,
                     "principal_user_detection_sources": ["logged_in_user"],
                     "principal_user_detection_domains": ["yolo.fr"],
                     "collected_condition_keys": collected_condition_keys,
                     "managed_installs_sync_interval_days": 1,
                     "script_checks_run_interval_seconds": 7231,
                     "auto_reinstall_incidents": True,
                     "auto_failed_install_incidents": False,
                     "created_at": configuration.created_at,
                     "updated_at": configuration.updated_at,
                     "version": 0,
                 }
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("munki:update_configuration", args=(configuration.pk,)))

    def test_update_configuration_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(reverse("munki:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_get(self):
        configuration = force_configuration()
        self._login("munki.change_configuration")
        response = self.client.get(reverse("munki:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_form.html")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_configuration_post(self, post_event):
        configuration = force_configuration()
        prev_updated_at = configuration.updated_at
        self._login("munki.change_configuration", "munki.view_configuration")
        collected_condition_keys = sorted(get_random_string(12) for _ in range(3))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("munki:update_configuration", args=(configuration.pk,)),
                                        {
                                            "name": configuration.name,
                                            "inventory_apps_full_info_shard": 17,
                                            "principal_user_detection_sources": "logged_in_user",
                                            "principal_user_detection_domains": "yolo.fr",
                                            "collected_condition_keys": ",".join(collected_condition_keys),
                                            "managed_installs_sync_interval_days": 2,
                                            "script_checks_run_interval_seconds": 3600,
                                            "auto_failed_install_incidents": "on"},
                                        follow=True
                                        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        configuration2 = response.context["object"]
        self.assertEqual(configuration2, configuration)
        self.assertEqual(configuration2.inventory_apps_full_info_shard, 17)
        self.assertEqual(configuration2.principal_user_detection_sources, ["logged_in_user"])
        self.assertEqual(configuration2.principal_user_detection_domains, ["yolo.fr"])
        self.assertEqual(configuration2.managed_installs_sync_interval_days, 2)
        self.assertEqual(configuration2.script_checks_run_interval_seconds, 3600)
        self.assertTrue(configuration2.auto_failed_install_incidents)
        self.assertEqual(sorted(configuration2.collected_condition_keys), collected_condition_keys)
        for condition_key in collected_condition_keys:
            self.assertContains(response, condition_key)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {
                "action": "updated",
                "object":
                {
                 "model": "munki.configuration",
                 "pk": str(configuration.pk),
                 "prev_value": {
                    "pk": configuration.pk,
                    "name": configuration.name,
                    "description": "",
                    "inventory_apps_full_info_shard": 100,
                    "principal_user_detection_sources": [],
                    "principal_user_detection_domains": [],
                    "collected_condition_keys": [],
                    "managed_installs_sync_interval_days": 7,
                    "script_checks_run_interval_seconds": 86400,
                    "auto_failed_install_incidents": False,
                    "auto_reinstall_incidents": False,
                    "created_at": configuration.created_at,
                    "updated_at": prev_updated_at,
                    "version": 0,
                 },
                 "new_value": {
                    "pk": configuration2.pk,
                    "description": "",
                    "name": configuration2.name,
                    "inventory_apps_full_info_shard": 17,
                    "principal_user_detection_sources": ["logged_in_user"],
                    "principal_user_detection_domains": ["yolo.fr"],
                    "collected_condition_keys": collected_condition_keys,
                    "managed_installs_sync_interval_days": 2,
                    "script_checks_run_interval_seconds": 3600,
                    "auto_failed_install_incidents": True,
                    "auto_reinstall_incidents": False,
                    "created_at": configuration2.created_at,
                    "updated_at": configuration2.updated_at,
                    "version": configuration2.version,
                 }
                }
            }
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])

    # create enrollment

    def test_create_enrollment_redirect(self):
        configuration = force_configuration()
        self._login_redirect(reverse("munki:create_enrollment", args=(configuration.pk,)))

    def test_create_enrollment_permission_denied(self):
        configuration = force_configuration()
        self._login()
        response = self.client.get(reverse("munki:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_get(self):
        configuration = force_configuration()
        self._login("munki.add_enrollment")
        response = self.client.get(reverse("munki:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertContains(response, "Munki enrollment")

    def test_create_enrollment_post_err(self):
        configuration = force_configuration()
        self._login("munki.add_enrollment", "munki.view_configuration", "munki.view_enrollment")
        response = self.client.post(reverse("munki:create_enrollment", args=(configuration.pk,)),
                                    {"configuration": 0,
                                     "secret-meta_business_unit": self.mbu.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertFormError(response.context["enrollment_form"], "configuration",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_create_enrollment_post(self):
        configuration = force_configuration()
        self._login("munki.add_enrollment", "munki.view_configuration", "munki.view_enrollment")
        response = self.client.post(reverse("munki:create_enrollment", args=(configuration.pk,)),
                                    {"configuration": configuration.pk,
                                     "secret-meta_business_unit": self.mbu.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        enrollment = response.context["enrollments"][0][0]
        self.assertEqual(enrollment.configuration, configuration)
        self.assertEqual(enrollment.secret.meta_business_unit, self.mbu)
        self.assertContains(response, enrollment.secret.meta_business_unit.name)

    # bump enrollment version

    def test_bump_enrollment_version_redirect(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login_redirect(reverse("munki:bump_enrollment_version",
                                     args=(enrollment.configuration.pk, enrollment.pk)))

    def test_bump_enrollment_version_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login()
        response = self.client.get(reverse("munki:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_bump_enrollment_version_get(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login("munki.change_enrollment")
        response = self.client.get(reverse("munki:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_confirm_version_bump.html")

    def test_bump_enrollment_version_post(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        version = enrollment.version
        self._login("munki.change_enrollment", "munki.view_configuration")
        response = self.client.post(reverse("munki:bump_enrollment_version",
                                            args=(enrollment.configuration.pk, enrollment.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.version, version + 1)

    # delete enrollment

    def test_delete_enrollment_redirect(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login_redirect(reverse("munki:delete_enrollment",
                                     args=(enrollment.configuration.pk, enrollment.pk)))

    def test_delete_enrollment_permission_denied(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login()
        response = self.client.get(reverse("munki:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_get(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login("munki.delete_enrollment")
        response = self.client.get(reverse("munki:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_confirm_delete.html")

    def test_delete_enrollment_post(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        self._login("munki.delete_enrollment", "munki.view_configuration")
        response = self.client.post(reverse("munki:delete_enrollment",
                                            args=(enrollment.configuration.pk, enrollment.pk)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_detail.html")
        ctx_configuration = response.context["configuration"]
        self.assertEqual(ctx_configuration, enrollment.configuration)
        self.assertEqual(ctx_configuration.enrollment_set.filter(pk=enrollment.pk).count(), 0)

    def test_delete_enrollment_distributor_404(self):
        enrollment = force_enrollment(meta_business_unit=self.mbu)
        enrollment.distributor_content_type = ContentType.objects.get(app_label="monolith",
                                                                      model="manifestenrollmentpackage")
        enrollment.distributor_pk = 1  # invalid, only for this test, not the reason for the 404!
        super(Enrollment, enrollment).save()  # to avoid calling the distributor callback
        self._login("munki.delete_enrollment")
        response = self.client.get(reverse("munki:delete_enrollment", args=(enrollment.configuration.pk,
                                                                            enrollment.pk)))
        self.assertEqual(response.status_code, 404)

    # terraform export

    def test_terraform_export_redirect(self):
        self._login_redirect(reverse("munki:terraform_export"))

    def test_terraform_export_permission_denied(self):
        self._login("munki.view_configuration")  # not enough
        response = self.client.get(reverse("munki:terraform_export"))
        self.assertEqual(response.status_code, 403)

    def test_terraform_export(self):
        self._login("munki.view_configuration", "munki.view_enrollment", "munki.view_scriptcheck")
        tag = Tag.objects.create(name=get_random_string(12))
        sc = force_script_check()
        sc.tags.set([tag])
        e = force_enrollment(meta_business_unit=self.mbu)
        cfg = e.configuration
        mbu = e.secret.meta_business_unit
        response = self.client.get(reverse("munki:terraform_export"))
        self.assertEqual(response.status_code, 200)
        with zipfile.ZipFile(io.BytesIO(response.content), mode="r") as zf:
            with zf.open("tags.tf") as ttf:
                self.assertEqual(
                    ttf.read().decode("utf-8"),
                    f'resource "zentral_tag" "tag{tag.pk}" {{\n'
                    f'  name = "{tag.name}"\n'
                    '}\n\n'
                )
            with zf.open("munki_configurations.tf") as mctf:
                self.assertEqual(
                    mctf.read().decode("utf-8"),
                    f'resource "zentral_munki_configuration" "configuration{cfg.pk}" {{\n'
                    f'  name = "{cfg.name}"\n'
                    '}\n\n'
                    f'resource "zentral_munki_enrollment" "enrollment{e.pk}" {{\n'
                    f'  configuration_id      = zentral_munki_configuration.configuration{cfg.pk}.id\n'
                    f'  meta_business_unit_id = zentral_meta_business_unit.metabusinessunit{mbu.pk}.id\n'
                    '}\n\n'
                )
            with zf.open("munki_script_checks.tf") as msctf:
                self.assertEqual(
                    msctf.read().decode("utf-8"),
                    f'resource "zentral_munki_script_check" "scriptcheck{sc.pk}" {{\n'
                    f'  name            = "{sc.compliance_check.name}"\n'
                    '  source          = "echo yolo"\n'
                    '  expected_result = "yolo"\n'
                    f'  tag_ids         = [zentral_tag.tag{tag.pk}.id]\n'
                    '}\n\n'
                )
