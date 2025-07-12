from datetime import datetime
from functools import reduce
import operator
from unittest.mock import patch
import uuid
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase, override_settings
from accounts.models import User
from zentral.contrib.inventory.compliance_checks import InventoryJMESPathCheck
from zentral.contrib.inventory.models import JMESPathCheck, MachineSnapshotCommit, MachineTag, MetaMachine, Source, Tag
from zentral.core.compliance_checks.models import ComplianceCheck, MachineStatus, Status
from zentral.core.stores.conf import stores
from zentral.utils.provisioning import provision


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class InventoryComplianceChecksViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
        stores._load(force=True)
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group] + stores.admin_console_store.events_url_authorized_roles)
        # machine
        cls.serial_number = "0123456789"
        cls.source_name = get_random_string(12) + "z"
        MachineSnapshotCommit.objects.commit_machine_snapshot_tree({
            "source": {"module": "tests.zentral.io", "name": cls.source_name.upper()},
            "serial_number": cls.serial_number,
            "os_version": {'name': 'OS X', 'major': 10, 'minor': 11, 'patch': 1},
            "osx_app_instances": [
                {'app': {'bundle_id': 'io.zentral.baller',
                         'bundle_name': 'Baller.app',
                         'bundle_version': '123',
                         'bundle_version_str': '1.2.3'},
                 'bundle_path': "/Applications/Baller.app"}
            ]
        })
        cls.source = Source.objects.get(name=cls.source_name.upper())
        cls.machine = MetaMachine(cls.serial_number)
        cls.url_msn = cls.machine.get_urlsafe_serial_number()

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

    def _force_jmespath_check(
        self,
        source_name=None,
        profile_uuid=None,
        jmespath_expression=None,
        tags=None,
        platforms=None
    ):
        if profile_uuid is None:
            profile_uuid = str(uuid.uuid4())
        if jmespath_expression is None:
            jmespath_expression = f"contains(profiles[*].uuid, `{profile_uuid}`)"
        cc = ComplianceCheck.objects.create(
            name=get_random_string(12),
            model=InventoryJMESPathCheck.get_model(),
        )
        if platforms is None:
            platforms = ["MACOS"]
        jmespath_check = JMESPathCheck.objects.create(
            compliance_check=cc,
            source_name=source_name or self.source_name,
            platforms=platforms,
            jmespath_expression=jmespath_expression
        )
        if tags is not None:
            jmespath_check.tags.set(tags)
        return jmespath_check

    # list

    def test_compliance_checks_redirect(self):
        self._login_redirect(reverse("inventory:compliance_checks"))

    def test_compliance_checks_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:compliance_checks"))
        self.assertEqual(response.status_code, 403)

    def test_compliance_checks_no_create_link(self):
        cc = self._force_jmespath_check()
        self._login("inventory.view_jmespathcheck")
        response = self.client.get(reverse("inventory:compliance_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_list.html")
        self.assertContains(response, cc.compliance_check.name)
        self.assertNotContains(response, reverse("inventory:create_compliance_check"))

    def test_compliance_checks_with_create_link(self):
        cc = self._force_jmespath_check()
        self._login("inventory.add_jmespathcheck", "inventory.view_jmespathcheck")
        response = self.client.get(reverse("inventory:compliance_checks"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_list.html")
        self.assertContains(response, cc.compliance_check.name)
        self.assertContains(response, reverse("inventory:create_compliance_check"))

    # create

    def test_create_compliance_check_redirect(self):
        self._login_redirect(reverse("inventory:create_compliance_check"))

    def test_create_compliance_check_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:create_compliance_check"))
        self.assertEqual(response.status_code, 403)

    def test_create_compliance_check_get(self):
        self._login("inventory.add_jmespathcheck")
        response = self.client.get(reverse("inventory:create_compliance_check"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Create compliance check")

    def test_create_compliance_check_devtool_pre_fill(self):
        self._login("inventory.add_jmespathcheck")
        source_name = get_random_string(12)
        jmespath_expression = "os_version.major > `11`"
        response = self.client.get(
            reverse("inventory:create_compliance_check"),
            {"source_name": source_name,
             "jmespath_expression": jmespath_expression}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Create compliance check")
        form = response.context["jmespath_check_form"]
        self.assertEqual(form.initial["source_name"], source_name)
        self.assertEqual(form.initial["jmespath_expression"], jmespath_expression)

    def test_create_compliance_check_post(self):
        self._login("inventory.add_jmespathcheck", "inventory.view_jmespathcheck")
        name = get_random_string(12)
        response = self.client.post(reverse("inventory:create_compliance_check"),
                                    {"ccf-name": name,
                                     "ccf-description": get_random_string(12),
                                     "jcf-source_name": get_random_string(12),
                                     "jcf-platforms": ["MACOS"],
                                     "jcf-jmespath_expression": "contains(profiles[*].uuid, `yolo`)"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_detail.html")
        self.assertContains(response, name)
        jmespath_check = response.context["object"]
        self.assertEqual(jmespath_check.platforms, ["MACOS"])

    def test_create_compliance_check_post_name_collision(self):
        cc = self._force_jmespath_check()
        self._login("inventory.add_jmespathcheck", "inventory.view_jmespathcheck")
        response = self.client.post(reverse("inventory:create_compliance_check"),
                                    {"ccf-name": cc.compliance_check.name,
                                     "ccf-description": get_random_string(12),
                                     "jcf-source_name": get_random_string(12),
                                     "jcf-platforms": ["MACOS"],
                                     "jcf-jmespath_expression": "contains(profiles[*].uuid, `yolo`)"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Inventory JMESPath check with this name already exists")

    def test_create_compliance_check_post_bad_jmespath_expression(self):
        self._login("inventory.add_jmespathcheck", "inventory.view_jmespathcheck")
        response = self.client.post(reverse("inventory:create_compliance_check"),
                                    {"ccf-name": get_random_string(12),
                                     "ccf-description": get_random_string(12),
                                     "jcf-source_name": get_random_string(12),
                                     "jcf-platforms": ["MACOS"],
                                     "jcf-jmespath_expression": "contains("},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Invalid JMESPath expression")

    # view

    def test_compliance_check_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(cc.get_absolute_url())

    def test_compliance_check_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(cc.get_absolute_url())
        self.assertEqual(response.status_code, 403)

    def test_compliance_check(self):
        cc = self._force_jmespath_check()
        self._login("inventory.view_jmespathcheck")
        response = self.client.get(cc.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_detail.html")
        self.assertContains(response, cc.compliance_check.name)
        self.assertContains(response, f"/inventory/compliance_checks/{cc.pk}/events/store_redirect/")

    # events

    def test_cc_events_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("inventory:compliance_check_events", args=(cc.pk,)))

    def test_cc_events_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("inventory:compliance_check_events", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.get_aggregated_object_event_counts")
    def test_cc_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        cc = self._force_jmespath_check()
        self._login("inventory.view_jmespathcheck")
        response = self.client.get(reverse("inventory:compliance_check_events", args=(cc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_events.html")

    # fetch events

    def test_cc_fetch_events_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("inventory:fetch_compliance_check_events", args=(cc.pk,)))

    def test_cc_fetch_events_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("inventory:fetch_compliance_check_events", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.ElasticsearchStore.fetch_object_events")
    def test_cc_fetch_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        cc = self._force_jmespath_check()
        self._login("inventory.view_jmespathcheck")
        response = self.client.get(reverse("inventory:fetch_compliance_check_events", args=(cc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    # events store redirect

    def test_cc_events_store_redirect_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("inventory:compliance_check_events_store_redirect", args=(cc.pk,)))

    def test_cc_events_store_redirect_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("inventory:compliance_check_events_store_redirect", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_cc_events_store_redirect(self):
        cc = self._force_jmespath_check()
        self._login("inventory.view_jmespathcheck")
        response = self.client.get(reverse("inventory:compliance_check_events_store_redirect", args=(cc.pk,)))
        # dev store cannot redirect
        self.assertRedirects(response, reverse("inventory:compliance_check_events", args=(cc.pk,)))

    # update

    def test_update_compliance_check_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("inventory:update_compliance_check", args=(cc.pk,)))

    def test_update_compliance_check_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("inventory:update_compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_compliance_check_get(self):
        cc = self._force_jmespath_check()
        self._login("inventory.change_jmespathcheck")
        response = self.client.get(reverse("inventory:update_compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Update compliance check")

    def test_update_compliance_check_post(self):
        cc = self._force_jmespath_check()
        old_version = cc.compliance_check.version
        self._login("inventory.change_jmespathcheck", "inventory.view_jmespathcheck")
        name = get_random_string(12)
        response = self.client.post(reverse("inventory:update_compliance_check", args=(cc.pk,)),
                                    {"ccf-name": name,
                                     "ccf-description": cc.compliance_check.description,
                                     "jcf-source_name": cc.source_name,
                                     "jcf-platforms": cc.platforms,
                                     "initial-jcf-platforms": cc.platforms,  # required for has_changed() to work!
                                     "jcf-jmespath_expression": cc.jmespath_expression},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_detail.html")
        self.assertNotContains(response, cc.compliance_check.name)
        self.assertContains(response, name)
        cc.refresh_from_db()
        cc.compliance_check.refresh_from_db()
        self.assertEqual(cc.compliance_check.name, name)
        self.assertEqual(cc.compliance_check.version, old_version)  # only the name changed → same version

    def test_update_compliance_check_post_updated_version(self):
        cc = self._force_jmespath_check()
        old_version = cc.compliance_check.version
        self._login("inventory.change_jmespathcheck", "inventory.view_jmespathcheck")
        source_name = get_random_string(12)
        response = self.client.post(reverse("inventory:update_compliance_check", args=(cc.pk,)),
                                    {"ccf-name": cc.compliance_check.name,
                                     "ccf-description": cc.compliance_check.description,
                                     "jcf-source_name": source_name,
                                     "jcf-platforms": ["IPADOS", "MACOS"],
                                     "initial-jcf-platforms": cc.platforms,  # required for has_changed() to work!
                                     "jcf-jmespath_expression": cc.jmespath_expression},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_detail.html")
        self.assertNotContains(response, cc.source_name)
        self.assertContains(response, source_name)
        cc.refresh_from_db()
        self.assertEqual(cc.source_name, source_name)
        cc.compliance_check.refresh_from_db()
        # source name and platforms changed → version updated
        self.assertEqual(cc.compliance_check.version, old_version + 1)
        self.assertEqual(sorted(cc.platforms), ["IPADOS", "MACOS"])

    def test_update_compliance_check_post_name_collision(self):
        cc0 = self._force_jmespath_check()
        cc = self._force_jmespath_check()
        self._login("inventory.change_jmespathcheck", "inventory.view_jmespathcheck")
        response = self.client.post(reverse("inventory:update_compliance_check", args=(cc.pk,)),
                                    {"ccf-name": cc0.compliance_check.name,
                                     "ccf-description": cc.compliance_check.description,
                                     "jcf-source_name": cc.source_name,
                                     "jcf-jmespath_expression": cc.jmespath_expression},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        self.assertContains(response, "Inventory JMESPath check with this name already exists")

    # delete

    def test_delete_compliance_check_redirect(self):
        cc = self._force_jmespath_check()
        self._login_redirect(reverse("inventory:delete_compliance_check", args=(cc.pk,)))

    def test_delete_compliance_check_permission_denied(self):
        cc = self._force_jmespath_check()
        self._login()
        response = self.client.get(reverse("inventory:delete_compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_compliance_check_get(self):
        cc = self._force_jmespath_check()
        self._login('inventory.delete_jmespathcheck')
        response = self.client.get(reverse("inventory:delete_compliance_check", args=(cc.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_confirm_delete.html")
        self.assertContains(response, cc.compliance_check.name)

    def test_delete_compliance_check_post(self):
        cc0 = self._force_jmespath_check()
        cc = self._force_jmespath_check()
        cc_pk = cc.pk
        self._login('inventory.delete_jmespathcheck', 'inventory.view_jmespathcheck')
        response = self.client.post(reverse("inventory:delete_compliance_check", args=(cc_pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_list.html")
        self.assertNotContains(response, reverse('inventory:compliance_check', args=(cc_pk,)))
        self.assertContains(response, cc0.compliance_check.name)
        self.assertContains(response, reverse('inventory:compliance_check', args=(cc0.pk,)))

    # devtool

    def test_compliance_check_devtool_redirect(self):
        self._login_redirect(reverse("inventory:compliance_check_devtool"))

    def test_compliance_check_devtool_permission_denied(self):
        self._login()
        response = self.client.get(reverse("inventory:compliance_check_devtool"))
        self.assertEqual(response.status_code, 403)

    def test_compliance_check_devtool_no_create(self):
        self._login('inventory.view_machinesnapshot')
        response = self.client.get(reverse("inventory:compliance_check_devtool"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertNotContains(response, "Create")

    def test_compliance_check_devtool_with_create(self):
        self._login('inventory.view_machinesnapshot', 'inventory.add_jmespathcheck')
        response = self.client.get(reverse("inventory:compliance_check_devtool"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertContains(response, "Create")

    def test_compliance_check_devtool_invalid_jmespath(self):
        self._login('inventory.view_machinesnapshot')
        response = self.client.post(
            reverse("inventory:compliance_check_devtool"),
            {"source": self.source.pk,
             "serial_number": self.serial_number,
             "jmespath_expression": "os_version.major >>>"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertFormError(
            response.context["form"],
            "jmespath_expression", "Invalid JMESPath expression"
        )
        self.assertEqual(response.context["tree"]["serial_number"], self.serial_number)
        self.assertIsNone(response.context.get("result"))

    def test_compliance_check_devtool_machine_not_found(self):
        self._login('inventory.view_machinesnapshot')
        response = self.client.post(
            reverse("inventory:compliance_check_devtool"),
            {"source": self.source.pk,
             "serial_number": get_random_string(12),
             "jmespath_expression": "os_version.major > `11`"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertFormError(
            response.context["form"],
            "serial_number", "Current machine with this serial number for this source not found"
        )
        self.assertIsNone(response.context.get("tree"))
        self.assertIsNone(response.context.get("result"))

    def test_compliance_check_devtool_not_a_bool(self):
        self._login('inventory.view_machinesnapshot')
        response = self.client.post(
            reverse("inventory:compliance_check_devtool"),
            {"source": self.source.pk,
             "serial_number": self.serial_number,
             "jmespath_expression": "os_version.major"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertFormError(
            response.context["form"],
            "jmespath_expression", "Result is not a boolean"
        )
        self.assertEqual(response.context["tree"]["serial_number"], self.serial_number)
        self.assertEqual(response.context["result"],  10)

    def test_compliance_check_devtool_test(self):
        self._login('inventory.view_machinesnapshot')
        response = self.client.post(
            reverse("inventory:compliance_check_devtool"),
            {"source": self.source.pk,
             "serial_number": self.serial_number,
             "jmespath_expression": "os_version.major > `9`"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_devtool.html")
        self.assertEqual(response.context["form"].errors, {})
        self.assertEqual(response.context["tree"]["serial_number"], self.serial_number)
        self.assertEqual(response.context["result"],  True)

    def test_compliance_check_devtool_create(self):
        self._login('inventory.view_machinesnapshot', 'inventory.add_jmespathcheck')
        response = self.client.post(
            reverse("inventory:compliance_check_devtool"),
            {"action": "create",
             "source": self.source.pk,
             "serial_number": self.serial_number,
             "jmespath_expression": "os_version.major > `9`"},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/compliancecheck_form.html")
        form = response.context["jmespath_check_form"]
        self.assertEqual(form.initial["source_name"], self.source.name)
        self.assertEqual(form.initial["jmespath_expression"], "os_version.major > `9`")

    # terraform export

    def test_compliance_check_terraform_export_redirect(self):
        self._login_redirect(reverse("inventory:compliance_check_terraform_export"))

    def test_compliance_check_terraform_export(self):
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        self._force_jmespath_check(tags=cc_tags)
        self._login('inventory.view_jmespathcheck')
        response = self.client.get(reverse("inventory:compliance_check_terraform_export"))
        self.assertEqual(response.status_code, 200)

    # machine

    def test_machine_no_compliance_checks(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance checks (0)</h3>")

    def test_machine_no_tags_no_compliance_checks_in_scope(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        self._force_jmespath_check(tags=cc_tags)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance checks (0)</h3>")

    def test_machine_with_tag_no_compliance_checks_in_scope(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        MachineTag.objects.get_or_create(serial_number=self.machine.serial_number,
                                         tag=Tag.objects.create(name=get_random_string(12)))
        self._force_jmespath_check(tags=cc_tags)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance checks (0)</h3>")

    def test_machine_source_mismatch_no_compliance_checks_in_scope(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        self._force_jmespath_check(source_name=get_random_string(12))
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance checks (0)</h3>")

    def test_machine_source_match_platform_missmatch_no_compliance_checks_in_scope(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        self._force_jmespath_check(platforms=["IPADOS"])
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance checks (0)</h3>")

    def test_machine_source_match_one_compliance_checks_in_scope(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        cc = self._force_jmespath_check()  # cls.source_name by default, test is case incensitive
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance check (1)</h3>")
        self.assertContains(response, "0 OK, 1 Pending")
        self.assertContains(response, cc.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,))
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], cc_redirect_link)
        self.assertEqual(compliance_check_statuses[0][1], cc.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.PENDING)

    def test_machine_no_tags_compliance_checks_one_in_scope_one_out_of_scope_pending_with_link(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        cc_without_tag = self._force_jmespath_check()
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        cc_with_tags = self._force_jmespath_check(tags=cc_tags)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance check (1)</h3>")
        self.assertContains(response, "0 OK, 1 Pending")
        self.assertContains(response, cc_without_tag.compliance_check.name)
        self.assertNotContains(response, cc_with_tags.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc_without_tag.compliance_check.pk,))
        self.assertContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], cc_redirect_link)
        self.assertEqual(compliance_check_statuses[0][1], cc_without_tag.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.PENDING)

    def test_machine_no_tags_compliance_checks_one_in_scope_one_out_of_scope_pending_without_link(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            # no view_jmespathcheck, no link
        )
        cc_without_tag = self._force_jmespath_check()
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        cc_with_tags = self._force_jmespath_check(tags=cc_tags)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance check (1)</h3>")
        self.assertContains(response, "0 OK, 1 Pending")
        self.assertContains(response, cc_without_tag.compliance_check.name)
        self.assertNotContains(response, cc_with_tags.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc_without_tag.compliance_check.pk,))
        self.assertNotContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], None)
        self.assertEqual(compliance_check_statuses[0][1], cc_without_tag.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.PENDING)

    def test_machine_no_tags_compliance_checks_one_in_scope_one_out_of_scope_no_section(self):
        self._login(
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck',
            # no compliance_checks.view_machinestatus, no section
        )
        cc_without_tag = self._force_jmespath_check()
        cc_tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(1)]
        self._force_jmespath_check(tags=cc_tags)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertNotContains(response, "<h3>Compliance check (1)</h3>")
        self.assertNotContains(response, cc_without_tag.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc_without_tag.compliance_check.pk,))
        self.assertNotContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 0)

    def test_machine_tags_once_compliance_check_in_scope_ok_with_link(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        for tag in tags[:3]:
            MachineTag.objects.get_or_create(serial_number=self.machine.serial_number, tag=tag)
        cc = self._force_jmespath_check(tags=tags)
        MachineStatus.objects.create(
            serial_number=self.machine.serial_number,
            compliance_check=cc.compliance_check,
            compliance_check_version=cc.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime.utcnow(),
        )
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance check (1)</h3>")
        self.assertContains(response, "1 OK")
        self.assertContains(response, cc.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,))
        self.assertContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], cc_redirect_link)
        self.assertEqual(compliance_check_statuses[0][1], cc.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.OK)

    def test_machine_tags_once_compliance_check_in_scope_two_different_statuses_ok_with_link(self):
        self._login(
            'compliance_checks.view_machinestatus',
            'inventory.view_machinesnapshot',
            'inventory.view_jmespathcheck'
        )
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        for tag in tags[:3]:
            MachineTag.objects.get_or_create(serial_number=self.machine.serial_number, tag=tag)
        cc = self._force_jmespath_check(tags=tags)
        MachineStatus.objects.create(
            serial_number=self.machine.serial_number,
            compliance_check=cc.compliance_check,
            compliance_check_version=cc.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime.utcnow(),
        )
        # add machine status for another machine also in scope
        other_machine_serial_number = get_random_string(12)
        MachineStatus.objects.create(
            serial_number=other_machine_serial_number,
            compliance_check=cc.compliance_check,
            compliance_check_version=cc.compliance_check.version,
            status=Status.OK.value,
            status_time=datetime.utcnow(),
        )
        for tag in tags[:3]:
            MachineTag.objects.get_or_create(serial_number=other_machine_serial_number, tag=tag)
        response = self.client.get(self.machine.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "inventory/machine_detail.html")
        self.assertContains(response, "<h3>Compliance check (1)</h3>")
        self.assertContains(response, "1 OK")
        self.assertContains(response, cc.compliance_check.name)
        cc_redirect_link = reverse("compliance_checks:redirect", args=(cc.compliance_check.pk,))
        self.assertContains(response, cc_redirect_link)
        compliance_check_statuses = response.context["compliance_check_statuses"]
        self.assertEqual(len(compliance_check_statuses), 1)
        self.assertEqual(compliance_check_statuses[0][0], cc_redirect_link)
        self.assertEqual(compliance_check_statuses[0][1], cc.compliance_check.name)
        self.assertEqual(compliance_check_statuses[0][2], Status.OK)
