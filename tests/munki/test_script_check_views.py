from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from zentral.core.compliance_checks.models import ComplianceCheck
from zentral.contrib.inventory.models import Tag
from zentral.contrib.munki.models import ScriptCheck
from zentral.core.events.base import AuditEvent
from accounts.models import User
from .utils import force_script_check


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class MunkiScriptCheckViewsTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

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

    # list

    def test_script_checks_redirect(self):
        self._login_redirect(reverse("munki:script_checks"))

    def test_script_checks_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:script_checks"))
        self.assertEqual(response.status_code, 403)

    def test_script_checks_no_links(self):
        sc = force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertContains(response, sc.compliance_check.name)
        self.assertNotContains(response, reverse("munki:create_script_check"))
        self.assertNotContains(response, reverse("munki:delete_script_check", args=(sc.pk,)))
        self.assertNotContains(response, reverse("munki:update_script_check", args=(sc.pk,)))

    def test_script_checks_all_link(self):
        sc_one = force_script_check()
        sc_two = force_script_check()
        self._login("munki.view_scriptcheck", "munki.add_scriptcheck",
                    "munki.change_scriptcheck", "munki.delete_scriptcheck")
        response = self.client.get(reverse("munki:script_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertContains(response, reverse("munki:create_script_check"))
        self.assertContains(response, sc_one.compliance_check.name)
        self.assertContains(response, sc_two.compliance_check.name)
        self.assertContains(response, "Script checks (2)")
        self.assertContains(response, reverse("munki:delete_script_check", args=(sc_one.pk,)))
        self.assertContains(response, reverse("munki:update_script_check", args=(sc_one.pk,)))

    def test_script_check_no_search_no_script_checks(self):
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertNotContains(response, "We didn't find any item related to your search")

    def test_script_check_search_no_match(self):
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_checks"), {"name": get_random_string(12)})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertContains(response, "Script checks (0)")
        self.assertContains(response, "We didn't find any item related to your search")

    def test_script_check_search_two_matches(self):
        self.user.items_per_page = 1
        self.user.save()
        sc_a = force_script_check()
        sc_b = force_script_check()
        sc_b.compliance_check.name = sc_a.compliance_check.name + " " + sc_b.compliance_check.name
        sc_b.compliance_check.save()
        force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_checks"), {"name": sc_a.compliance_check.name,
                                                                    "type": sc_a.type,
                                                                    "page": 2})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertContains(response, "Script checks (2)")
        self.assertContains(response, "page 2 of 2")
        self.assertNotContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("munki:script_checks"))
        self.assertContains(response, sc_b.compliance_check.name)

    # create

    def test_create_script_check_redirect(self):
        self._login_redirect(reverse("munki:create_script_check"))

    def test_create_script_check_permission_denied(self):
        self._login()
        response = self.client.get(reverse("munki:create_script_check"))
        self.assertEqual(response.status_code, 403)

    def test_create_script_check_get(self):
        self._login("munki.add_scriptcheck")
        response = self.client.get(reverse("munki:create_script_check"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertContains(response, "Create script check")

    def test_create_script_check_post_no_arch_err(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "ccf-description": description,
             "scf-type": "ZSH_STR",
             "scf-source": "echo yolo",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": False,
             "scf-arch_arm64": False},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        err_msg = "This check has to run on at least one architecture"
        self.assertFormError(response.context["script_check_form"], "arch_amd64", err_msg)
        self.assertFormError(response.context["script_check_form"], "arch_arm64", err_msg)

    def test_create_script_check_post_os_errors(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "ccf-description": description,
             "scf-type": "ZSH_STR",
             "scf-source": "echo yolo",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": True,
             "scf-arch_arm64": True,
             "scf-min_os_version": "yolo",
             "scf-max_os_version": "fomo"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        err_msg = "Not a valid OS version"
        self.assertFormError(response.context["script_check_form"], "min_os_version", err_msg)
        self.assertFormError(response.context["script_check_form"], "max_os_version", err_msg)

    def test_create_script_check_post_int_err(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "ccf-description": description,
             "scf-type": "ZSH_INT",
             "scf-source": "echo 1",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": False,
             "scf-arch_arm64": False},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertFormError(response.context["script_check_form"], "expected_result", "Invalid integer")

    def test_create_script_check_post_bool_err(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "ccf-description": description,
             "scf-type": "ZSH_BOOL",
             "scf-source": "echo 1",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": False,
             "scf-arch_arm64": False},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertFormError(response.context["script_check_form"], "expected_result", "Invalid boolean")

    def test_create_script_check_post_tag_sets_not_disjoint_err(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "scf-type": "ZSH_STR",
             "scf-source": "echo yolo",
             "scf-expected_result": "yolo",
             "scf-arch_arm64": True,
             "scf-tags": [t.pk for t in tags[:-1]],
             "scf-excluded_tags": [t.pk for t in tags[1:]]},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertFormError(response.context["script_check_form"],
                             "excluded_tags", "tags and excluded tags must be disjoint")

    def test_create_script_check_post_min_os_version_err(self):
        self._login("munki.add_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        response = self.client.post(
            reverse("munki:create_script_check"),
            {"ccf-name": name,
             "ccf-description": description,
             "scf-type": "ZSH_BOOL",
             "scf-source": "echo 1",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": True,
             "scf-arch_arm64": True,
             "scf-min_os_version": "14.1",
             "scf-max_os_version": "14.0.1"},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertFormError(response.context["script_check_form"],
                             "min_os_version", "Should be smaller than the max OS version")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_script_check_post_ok(self, post_event):
        self._login("munki.add_scriptcheck", "munki.view_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        excluded_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("munki:create_script_check"),
                {"ccf-name": name,
                 "ccf-description": description,
                 "scf-type": "ZSH_BOOL",
                 "scf-source": "echo true",
                 "scf-expected_result": "True",
                 "scf-tags": [t.pk for t in tags],
                 "scf-excluded_tags": [t.pk for t in excluded_tags],
                 "scf-arch_amd64": False,
                 "scf-arch_arm64": True,
                 "scf-min_os_version": "14",
                 "scf-max_os_version": "15"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "munki/scriptcheck_detail.html")
        self.assertContains(response, name)
        script_check = response.context["object"]
        self.assertEqual(script_check.compliance_check.name, name)
        self.assertEqual(script_check.compliance_check.description, description)
        self.assertEqual(script_check.compliance_check.version, 1)
        self.assertEqual(script_check.type, "ZSH_BOOL")
        self.assertEqual(script_check.source, "echo true")
        self.assertEqual(script_check.expected_result, "True")
        self.assertEqual(set(script_check.tags.all()), set(tags))
        self.assertEqual(set(script_check.excluded_tags.all()), set(excluded_tags))
        self.assertFalse(script_check.arch_amd64)
        self.assertTrue(script_check.arch_arm64)
        self.assertEqual(script_check.min_os_version, "14")
        self.assertEqual(script_check.max_os_version, "15")
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(script_check.pk),
                 "new_value": {
                     "pk": script_check.pk,
                     "compliance_check": {
                         "pk": script_check.compliance_check.pk,
                         "name": script_check.compliance_check.name,
                         "model": "MunkiScriptCheck",
                         "description": script_check.compliance_check.description,
                         "version": 1,
                     },
                     "type": "ZSH_BOOL",
                     "source": "echo true",
                     "expected_result": "True",
                     "tags": [{"pk": t.pk, "name": t.name}
                              for t in sorted(tags, key=lambda t: t.pk)],
                     "excluded_tags": [{"pk": t.pk, "name": t.name}
                                       for t in sorted(excluded_tags, key=lambda t: t.pk)],
                     "arch_amd64": False,
                     "arch_arm64": True,
                     "min_os_version": "14",
                     "max_os_version": "15",
                     "created_at": script_check.created_at,
                     "updated_at": script_check.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(script_check.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])

    # view

    def test_view_script_check_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:script_check", args=(sc.pk,)))

    def test_view_script_check_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_view_script_check_no_links(self):
        sc = force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_detail.html")
        self.assertContains(response, sc.compliance_check.name)
        self.assertNotContains(response, reverse("munki:update_script_check", args=(sc.pk,)))
        self.assertNotContains(response, reverse("munki:delete_script_check", args=(sc.pk,)))

    def test_view_script_check_update_link(self):
        sc = force_script_check()
        self._login("munki.view_scriptcheck", "munki.change_scriptcheck")
        response = self.client.get(reverse("munki:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_detail.html")
        self.assertContains(response, sc.compliance_check.name)
        self.assertContains(response, reverse("munki:update_script_check", args=(sc.pk,)))
        self.assertNotContains(response, reverse("munki:delete_script_check", args=(sc.pk,)))

    def test_view_script_check_delete_link(self):
        sc = force_script_check()
        self._login("munki.view_scriptcheck", "munki.delete_scriptcheck")
        response = self.client.get(reverse("munki:script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_detail.html")
        self.assertContains(response, sc.compliance_check.name)
        self.assertNotContains(response, reverse("munki:update_script_check", args=(sc.pk,)))
        self.assertContains(response, reverse("munki:delete_script_check", args=(sc.pk,)))

    # update

    def test_update_script_check_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:update_script_check", args=(sc.pk,)))

    def test_update_script_check_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:update_script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_script_check_get(self):
        sc = force_script_check()
        self._login("munki.change_scriptcheck")
        response = self.client.get(reverse("munki:update_script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertContains(response, "Update script check")

    def test_update_script_post_arch_err(self):
        sc = force_script_check()
        self._login("munki.change_scriptcheck")
        response = self.client.post(
            reverse("munki:update_script_check", args=(sc.pk,)),
            {"ccf-name": "yolo",
             "ccf-description": "fomo",
             "scf-type": "ZSH_INT",
             "scf-source": "echo 1",
             "scf-expected_result": "yolo",
             "scf-arch_amd64": False,
             "scf-arch_arm64": False},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_form.html")
        self.assertFormError(response.context["script_check_form"], "expected_result", "Invalid integer")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_script_check_post_ok(self, post_event):
        sc = force_script_check()
        prev_value = sc.serialize_for_event()
        self._login("munki.change_scriptcheck", "munki.view_scriptcheck")
        name = get_random_string(12)
        description = get_random_string(12)
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        excluded_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(2)]
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("munki:update_script_check", args=(sc.pk,)),
                {"ccf-name": name,
                 "ccf-description": description,
                 "scf-type": "ZSH_BOOL",
                 "scf-source": "echo true",
                 "scf-expected_result": "True",
                 "scf-tags": [t.pk for t in tags],
                 "scf-excluded_tags": [t.pk for t in excluded_tags],
                 "scf-arch_amd64": False,
                 "scf-arch_arm64": True,
                 "scf-min_os_version": "14",
                 "scf-max_os_version": "15"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "munki/scriptcheck_detail.html")
        self.assertContains(response, name)
        script_check = response.context["object"]
        self.assertEqual(script_check.compliance_check.name, name)
        self.assertEqual(script_check.compliance_check.description, description)
        self.assertEqual(script_check.compliance_check.version, 2)
        self.assertEqual(script_check.type, "ZSH_BOOL")
        self.assertEqual(script_check.source, "echo true")
        self.assertEqual(script_check.expected_result, "True")
        self.assertEqual(set(script_check.tags.all()), set(tags))
        self.assertEqual(set(script_check.excluded_tags.all()), set(excluded_tags))
        self.assertFalse(script_check.arch_amd64)
        self.assertTrue(script_check.arch_arm64)
        self.assertEqual(script_check.min_os_version, "14")
        self.assertEqual(script_check.max_os_version, "15")
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "updated",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(script_check.pk),
                 "prev_value": prev_value,
                 "new_value": {
                     "pk": script_check.pk,
                     "compliance_check": {
                         "pk": script_check.compliance_check.pk,
                         "name": script_check.compliance_check.name,
                         "model": "MunkiScriptCheck",
                         "description": script_check.compliance_check.description,
                         "version": 2,
                     },
                     "type": "ZSH_BOOL",
                     "source": "echo true",
                     "expected_result": "True",
                     "tags": [{"pk": t.pk, "name": t.name}
                              for t in sorted(tags, key=lambda t: t.pk)],
                     "excluded_tags": [{"pk": t.pk, "name": t.name}
                                       for t in sorted(excluded_tags, key=lambda t: t.pk)],
                     "arch_amd64": False,
                     "arch_arm64": True,
                     "min_os_version": "14",
                     "max_os_version": "15",
                     "created_at": script_check.created_at,
                     "updated_at": script_check.updated_at,
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(script_check.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])

    # delete

    def test_delete_script_check_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:delete_script_check", args=(sc.pk,)))

    def test_delete_script_check_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:delete_script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_script_check_get(self):
        sc = force_script_check()
        self._login("munki.delete_scriptcheck")
        response = self.client.get(reverse("munki:delete_script_check", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_confirm_delete.html")
        self.assertContains(response, sc.compliance_check.name)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_script_check_post(self, post_event):
        sc = force_script_check()
        prev_value = sc.serialize_for_event()
        prev_pk = sc.pk
        prev_name = sc.compliance_check.name
        prev_cc_pk = sc.compliance_check.pk
        self._login("munki.delete_scriptcheck", "munki.view_scriptcheck")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("munki:delete_script_check", args=(sc.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "munki/scriptcheck_list.html")
        self.assertNotContains(response, prev_name)
        self.assertFalse(ScriptCheck.objects.filter(pk=prev_pk).exists())
        self.assertFalse(ComplianceCheck.objects.filter(pk=prev_cc_pk).exists())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "deleted",
             "object": {
                 "model": "munki.scriptcheck",
                 "pk": str(prev_pk),
                 "prev_value": prev_value,
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"munki_script_check": [str(prev_pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["munki", "zentral"])

    # events

    def test_script_check_events_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:script_check_events", args=(sc.pk,)))

    def test_script_check_events_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:script_check_events", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_script_check_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        sc = force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_check_events", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "munki/scriptcheck_events.html")

    # fetch events

    def test_script_check_fetch_events_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:fetch_script_check_events", args=(sc.pk,)))

    def test_script_check_fetch_events_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:fetch_script_check_events", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_script_check_fetch_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        sc = force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:fetch_script_check_events", args=(sc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # events store redirect

    def test_script_check_events_store_redirect_redirect(self):
        sc = force_script_check()
        self._login_redirect(reverse("munki:script_check_events_store_redirect", args=(sc.pk,)))

    def test_script_check_events_store_redirect_permission_denied(self):
        sc = force_script_check()
        self._login()
        response = self.client.get(reverse("munki:script_check_events_store_redirect", args=(sc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_script_check_events_store_redirect(self):
        sc = force_script_check()
        self._login("munki.view_scriptcheck")
        response = self.client.get(reverse("munki:script_check_events_store_redirect", args=(sc.pk,)))
        # dev store cannot redirect
        self.assertRedirects(response, reverse("munki:script_check_events", args=(sc.pk,)))
