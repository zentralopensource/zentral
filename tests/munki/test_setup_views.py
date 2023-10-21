from functools import reduce
import json
import operator
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit
from zentral.contrib.munki.models import Configuration, Enrollment
from accounts.models import User


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
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

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def _force_enrollment(self):
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.mbu)
        return Enrollment.objects.create(configuration=self._force_configuration(), secret=enrollment_secret)

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

    def test_create_configuration_post(self):
        self._login("munki.add_configuration", "munki.view_configuration")
        name = get_random_string(12)
        description = get_random_string(12)
        collected_condition_keys = sorted(get_random_string(12) for _ in range(3))
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

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("munki:update_configuration", args=(configuration.pk,)))

    def test_update_configuration_permission_denied(self):
        configuration = self._force_configuration()
        self._login()
        response = self.client.get(reverse("munki:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_get(self):
        configuration = self._force_configuration()
        self._login("munki.change_configuration")
        response = self.client.get(reverse("munki:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/configuration_form.html")

    def test_update_configuration_post(self):
        configuration = self._force_configuration()
        self._login("munki.change_configuration", "munki.view_configuration")
        collected_condition_keys = sorted(get_random_string(12) for _ in range(3))
        response = self.client.post(reverse("munki:update_configuration", args=(configuration.pk,)),
                                    {"name": configuration.name,
                                     "inventory_apps_full_info_shard": 17,
                                     "principal_user_detection_sources": "logged_in_user",
                                     "principal_user_detection_domains": "yolo.fr",
                                     "collected_condition_keys": ",".join(collected_condition_keys),
                                     "managed_installs_sync_interval_days": 2,
                                     "script_checks_run_interval_seconds": 3600,
                                     "auto_failed_install_incidents": "on"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
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

    # create enrollment

    def test_create_enrollment_redirect(self):
        configuration = self._force_configuration()
        self._login_redirect(reverse("munki:create_enrollment", args=(configuration.pk,)))

    def test_create_enrollment_permission_denied(self):
        configuration = self._force_configuration()
        self._login()
        response = self.client.get(reverse("munki:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_enrollment_get(self):
        configuration = self._force_configuration()
        self._login("munki.add_enrollment")
        response = self.client.get(reverse("munki:create_enrollment", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertContains(response, "Munki enrollment")

    def test_create_enrollment_post_err(self):
        configuration = self._force_configuration()
        self._login("munki.add_enrollment", "munki.view_configuration", "munki.view_enrollment")
        response = self.client.post(reverse("munki:create_enrollment", args=(configuration.pk,)),
                                    {"configuration": 0,
                                     "secret-meta_business_unit": self.mbu.pk}, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_form.html")
        self.assertFormError(response.context["enrollment_form"], "configuration",
                             "Select a valid choice. That choice is not one of the available choices.")

    def test_create_enrollment_post(self):
        configuration = self._force_configuration()
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
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("munki:bump_enrollment_version",
                                     args=(enrollment.configuration.pk, enrollment.pk)))

    def test_bump_enrollment_version_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("munki:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_bump_enrollment_version_get(self):
        enrollment = self._force_enrollment()
        self._login("munki.change_enrollment")
        response = self.client.get(reverse("munki:bump_enrollment_version",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_confirm_version_bump.html")

    def test_bump_enrollment_version_post(self):
        enrollment = self._force_enrollment()
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
        enrollment = self._force_enrollment()
        self._login_redirect(reverse("munki:delete_enrollment",
                                     args=(enrollment.configuration.pk, enrollment.pk)))

    def test_delete_enrollment_permission_denied(self):
        enrollment = self._force_enrollment()
        self._login()
        response = self.client.get(reverse("munki:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_enrollment_get(self):
        enrollment = self._force_enrollment()
        self._login("munki.delete_enrollment")
        response = self.client.get(reverse("munki:delete_enrollment",
                                           args=(enrollment.configuration.pk, enrollment.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/enrollment_confirm_delete.html")

    def test_delete_enrollment_post(self):
        enrollment = self._force_enrollment()
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
        enrollment = self._force_enrollment()
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
        self._login("munki.view_configuration", "munki.view_enrollment")
        self._force_enrollment()
        response = self.client.get(reverse("munki:terraform_export"))
        self.assertEqual(response.status_code, 200)
