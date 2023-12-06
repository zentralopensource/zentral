from datetime import datetime, time
from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Tag
from zentral.core.events.base import AuditEvent
from .utils import force_blueprint, force_software_update_enforcement


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SoftwareUpdateEnforcementViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # utiliy methods

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

    # SUE list

    def test_software_update_enforcements_redirect(self):
        self._login_redirect(reverse("mdm:software_update_enforcements"))

    def test_software_update_enforcements_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:software_update_enforcements"))
        self.assertEqual(response.status_code, 403)

    def test_software_update_enforcements_no_links(self):
        sue = force_software_update_enforcement()
        self._login("mdm.view_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:software_update_enforcements"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_list.html")
        self.assertContains(response, sue.name)
        self.assertNotContains(response, reverse("mdm:update_software_update_enforcement", args=(sue.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))

    def test_software_update_enforcements_all_links(self):
        sue1 = force_software_update_enforcement()
        force_blueprint(software_update_enforcement=sue1)
        sue2 = force_software_update_enforcement()
        self._login(
            "mdm.view_softwareupdateenforcement",
            "mdm.change_softwareupdateenforcement",
            "mdm.delete_softwareupdateenforcement"
        )
        response = self.client.get(reverse("mdm:software_update_enforcements"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_list.html")
        self.assertContains(response, sue1.name)
        self.assertContains(response, sue2.name)
        self.assertContains(response, reverse("mdm:update_software_update_enforcement", args=(sue1.pk,)))
        self.assertNotContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue1.pk,)))
        self.assertContains(response, reverse("mdm:update_software_update_enforcement", args=(sue2.pk,)))
        self.assertContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue2.pk,)))

    # create SUE

    def test_create_software_update_enforcement_redirect(self):
        self._login_redirect(reverse("mdm:create_software_update_enforcement"))

    def test_create_software_update_enforcement_permission_denied(self):
        self._login()
        response = self.client.get(reverse("mdm:create_software_update_enforcement"))
        self.assertEqual(response.status_code, 403)

    def test_create_software_update_enforcement_get(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:create_software_update_enforcement"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertContains(response, "Create software update enforcement")

    def test_create_software_update_enforcement_post_latest_delay_days_too_high(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                    {"name": get_random_string(12),
                                     "enforcement_type": "LATEST",
                                     "max_os_version": "19.0",
                                     "delay_days": 121,
                                     "local_time": "09:30:00"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertFormError(response.context["form"], "delay_days",
                             'Ensure this value is less than or equal to 120.')

    def test_create_software_update_enforcement_post_latest_missing_required_field(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                    {"name": get_random_string(12),
                                     "enforcement_type": "LATEST",
                                     "delay_days": 12,
                                     "local_time": "09:30:00"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertFormError(response.context["form"], "max_os_version", "This field is required")

    def test_create_software_update_enforcement_post_latest_bad_max_os_version(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                    {"name": get_random_string(12),
                                     "enforcement_type": "LATEST",
                                     "max_os_version": "ABC",
                                     "delay_days": 12,
                                     "local_time": "09:30:00"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertFormError(response.context["form"], "max_os_version", "Not a valid OS version")

    def test_create_software_update_enforcement_post_one_time_missing_required_field(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                    {"name": get_random_string(12),
                                     "enforcement_type": "ONE_TIME",
                                     "os_version": "14.1"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertFormError(response.context["form"], "local_datetime", "This field is required")

    def test_create_software_update_enforcement_post_one_time_bad_os_version(self):
        self._login("mdm.add_softwareupdateenforcement")
        response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                    {"name": get_random_string(12),
                                     "enforcement_type": "ONE_TIME",
                                     "os_version": "ABC",
                                     "local_datetime": "2023-11-10 09:30"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertFormError(response.context["form"], "os_version", "Not a valid OS version")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_software_update_enforcement_post_latest(self, post_event):
        self._login("mdm.add_softwareupdateenforcement", "mdm.view_softwareupdateenforcement")
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                        {"name": name,
                                         "details_url": "https://www.example.com",
                                         "platforms": ["iOS"],
                                         "enforcement_type": "LATEST",
                                         "max_os_version": "19.0",
                                         "delay_days": 12,
                                         "local_time": "9:30"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        sue = response.context["object"]
        self.assertEqual(sue.name, name)
        self.assertEqual(sue.tags.count(), 0)
        self.assertEqual(sue.details_url, "https://www.example.com")
        self.assertEqual(sue.platforms, ["iOS"])
        self.assertEqual(sue.max_os_version, "19.0")
        self.assertEqual(sue.delay_days, 12)
        self.assertEqual(sue.local_time, time(9, 30))
        self.assertEqual(sue.os_version, "")
        self.assertEqual(sue.build_version, "")
        self.assertIsNone(sue.local_datetime)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": name,
                     "platforms": ["iOS"],
                     "tags": [],
                     "details_url": "https://www.example.com",
                     "max_os_version": "19.0",
                     "delay_days": 12,
                     "local_time": "09:30:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_software_update_enforcement_one_time(self, post_event):
        self._login("mdm.add_softwareupdateenforcement", "mdm.view_softwareupdateenforcement")
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)], key=lambda t: t.pk)
        name = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:create_software_update_enforcement"),
                                        {"name": name,
                                         "details_url": "https://www.example.com",
                                         "platforms": ["macOS"],
                                         "tags": [t.pk for t in tags],
                                         "enforcement_type": "ONE_TIME",
                                         "os_version": "14.1",
                                         "build_version": "23B74",
                                         "local_datetime": "2023-11-10 09:30"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        sue = response.context["object"]
        self.assertEqual(sue.name, name)
        self.assertEqual(sue.details_url, "https://www.example.com")
        self.assertEqual(sue.platforms, ["macOS"])
        self.assertEqual(set(sue.tags.all()), set(tags))
        self.assertEqual(sue.os_version, "14.1")
        self.assertEqual(sue.build_version, "23B74")
        self.assertEqual(sue.local_datetime, datetime(2023, 11, 10, 9, 30))
        self.assertEqual(sue.max_os_version, "")
        self.assertIsNone(sue.delay_days)
        self.assertIsNone(sue.local_time)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "new_value": {
                     "pk": sue.pk,
                     "name": name,
                     "platforms": ["macOS"],
                     "tags": [{"pk": t.pk, "name": t.name} for t in tags],
                     "details_url": "https://www.example.com",
                     "os_version": "14.1",
                     "build_version": "23B74",
                     "local_datetime": "2023-11-10T09:30:00",
                     "created_at": sue.created_at,
                     "updated_at": sue.updated_at
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # SUE

    def test_software_update_enforcement_redirect(self):
        sue = force_software_update_enforcement()
        self._login_redirect(reverse("mdm:software_update_enforcement", args=(sue.pk,)))

    def test_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        self._login()
        response = self.client.get(reverse("mdm:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_software_update_enforcement_get(self):
        sue = force_software_update_enforcement()
        self._login("mdm.view_softwareupdateenforcement", "mdm.delete_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        self.assertContains(response, sue.name)
        self.assertContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))

    def test_software_update_enforcement_get_no_perm_no_delete_link(self):
        sue = force_software_update_enforcement()
        self._login("mdm.view_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        self.assertContains(response, sue.name)
        self.assertNotContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))

    def test_software_update_enforcement_get_cannot_be_deleted_no_delete_link(self):
        sue = force_software_update_enforcement()
        force_blueprint(software_update_enforcement=sue)
        self._login("mdm.view_softwareupdateenforcement", "mdm.delete_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        self.assertContains(response, sue.name)
        self.assertNotContains(response, reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))

    # update SUE

    def test_update_software_update_enforcement_redirect(self):
        sue = force_software_update_enforcement()
        self._login_redirect(reverse("mdm:update_software_update_enforcement", args=(sue.pk,)))

    def test_update_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        self._login()
        response = self.client.get(reverse("mdm:update_software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_software_update_enforcement_get(self):
        sue = force_software_update_enforcement()
        self._login("mdm.change_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:update_software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_form.html")
        self.assertContains(response, "Update software update enforcement")
        self.assertContains(response, sue.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_software_update_enforcement_post(self, post_event):
        sue = force_software_update_enforcement()
        prev_value = sue.serialize_for_event()
        self.assertEqual(sue.details_url, "")
        self.assertEqual(sue.tags.count(), 0)
        self.assertEqual(sue.os_version, "")
        self.assertEqual(sue.build_version, "")
        self.assertIsNone(sue.local_datetime)
        self._login("mdm.change_softwareupdateenforcement", "mdm.view_softwareupdateenforcement")
        new_name = get_random_string(12)
        tags = sorted([Tag.objects.create(name=get_random_string(12)) for _ in range(2)], key=lambda t: t.pk)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:update_software_update_enforcement", args=(sue.pk,)),
                                        {"name": new_name,
                                         "platforms": ["macOS"],
                                         "tags": [t.pk for t in tags],
                                         "details_url": "https://www.example.com",
                                         "enforcement_type": "ONE_TIME",
                                         "os_version": "14.1",
                                         "build_version": "23B74",
                                         "local_datetime": "2023-11-10 09:30"},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_detail.html")
        sue2 = response.context["object"]
        self.assertEqual(sue2, sue)
        self.assertEqual(sue2.name, new_name)
        self.assertEqual(sue2.details_url, "https://www.example.com")
        self.assertEqual(sue2.platforms, ["macOS"])
        self.assertEqual(sue2.os_version, "14.1")
        self.assertEqual(sue2.build_version, "23B74")
        self.assertEqual(sue2.local_datetime, datetime(2023, 11, 10, 9, 30))
        self.assertEqual(sue2.max_os_version, "")
        self.assertIsNone(sue2.local_time)
        self.assertIsNone(sue2.delay_days)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue2.pk),
                 "new_value": {
                     "pk": sue2.pk,
                     "name": new_name,
                     "platforms": ["macOS"],
                     "tags": [{"pk": t.pk, "name": t.name} for t in tags],
                     "details_url": "https://www.example.com",
                     "os_version": "14.1",
                     "build_version": "23B74",
                     "local_datetime": "2023-11-10T09:30:00",
                     "created_at": sue2.created_at,
                     "updated_at": sue2.updated_at
                 },
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])

    # delete FileVault configuration

    def test_delete_software_update_enforcement_redirect(self):
        sue = force_software_update_enforcement()
        self._login_redirect(reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))

    def test_delete_software_update_enforcement_permission_denied(self):
        sue = force_software_update_enforcement()
        self._login()
        response = self.client.get(reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_software_update_enforcement_404(self):
        sue = force_software_update_enforcement()
        force_blueprint(software_update_enforcement=sue)
        self._login("mdm.delete_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 404)

    def test_delete_software_update_enforcement_get(self):
        sue = force_software_update_enforcement()
        self._login("mdm.delete_softwareupdateenforcement")
        response = self.client.get(reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_confirm_delete.html")
        self.assertContains(response, "Delete software update enforcement")
        self.assertContains(response, sue.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_software_update_enforcement_post(self, post_event):
        sue = force_software_update_enforcement()
        prev_value = sue.serialize_for_event()
        self._login("mdm.delete_softwareupdateenforcement", "mdm.view_softwareupdateenforcement")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("mdm:delete_software_update_enforcement", args=(sue.pk,)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "mdm/softwareupdateenforcement_list.html")
        self.assertNotContains(response, sue.name)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "mdm.softwareupdateenforcement",
                 "pk": str(sue.pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"mdm_software_update_enforcement": [str(sue.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["mdm", "zentral"])
