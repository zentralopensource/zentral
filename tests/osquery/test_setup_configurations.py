from unittest.mock import patch
from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.osquery.utils import assert_audit_event
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.events.base import AuditEvent
from zentral.contrib.inventory.models import Tag
from zentral.contrib.osquery.models import (AutomaticTableConstruction, Configuration,
                                            ConfigurationPack, FileCategory, Pack, PackQuery, Query)


class OsquerySetupConfigurationsViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "osquery"

    # utility methods

    def _force_configuration(self):
        return Configuration.objects.create(name=get_random_string(12))

    def _force_pack(self):
        pack = Pack.objects.create(name=get_random_string(12))
        query = Query.objects.create(name=get_random_string(12), sql="select 1 from processes;")
        PackQuery.objects.create(pack=pack, query=query, interval=203)
        return pack

    def _force_configuration_pack(self):
        configuration = self._force_configuration()
        pack = self._force_pack()
        return ConfigurationPack.objects.create(configuration=configuration, pack=pack)

    # create configuration

    def test_create_configuration_redirect(self):
        self.login_redirect("create_configuration")

    def test_create_configuration_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:create_configuration"))
        self.assertEqual(response.status_code, 403)

    def test_create_configuration_get(self):
        self.login("osquery.add_configuration")
        response = self.client.get(reverse("osquery:create_configuration"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_form.html")
        self.assertContains(response, "Create Osquery configuration")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_configuration_post(self, post_event):
        self.login("osquery.add_configuration", "osquery.view_configuration")
        configuration_name = get_random_string(64)
        configuration_description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:create_configuration"),
                                        {"name": configuration_name,
                                         "description": configuration_description,
                                         "inventory_interval": 86321,
                                         "inventory_ec2": True},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, configuration_name)
        self.assertContains(response, configuration_description)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, configuration_name)
        self.assertEqual(configuration.description, configuration_description)
        self.assertEqual(configuration.inventory_interval, 86321)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "osquery.configuration",
                 "pk": str(configuration.pk),
                 "new_value": {
                     "pk": configuration.pk,
                     "name": configuration_name,
                     "description": configuration_description,
                     # unchecked checkboxes are not posted, so the model default of True does not apply
                     "inventory": False,
                     "inventory_apps": False,
                     "inventory_ec2": True,
                     "inventory_interval": 86321,
                     "options": {},
                     "file_categories": [],
                     "automatic_table_constructions": [],
                     "created_at": configuration.created_at.isoformat(),
                     "updated_at": configuration.updated_at.isoformat(),
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"osquery_configuration": [str(configuration.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["osquery", "zentral"])
        self.assertTrue(configuration.inventory_ec2)
        self.assertEqual(configuration.options, {})

    # update configuration

    def test_update_configuration_redirect(self):
        configuration = self._force_configuration()
        self.login_redirect("update_configuration", configuration.pk)

    def test_update_configuration_permission_denied(self):
        configuration = self._force_configuration()
        self.login()
        response = self.client.get(reverse("osquery:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_get(self):
        configuration = self._force_configuration()
        self.login("osquery.change_configuration")
        response = self.client.get(reverse("osquery:update_configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_form.html")
        self.assertContains(response, "Update Osquery configuration")

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_configuration_post(self, post_event):
        configuration = self._force_configuration()
        prev_value = configuration.serialize_for_event()
        self.login("osquery.change_configuration", "osquery.view_configuration")
        new_name = get_random_string(64)
        file_category = FileCategory.objects.create(name=get_random_string(12), slug=get_random_string(12))
        atc = AutomaticTableConstruction.objects.create(
            name=get_random_string(12),
            table_name=get_random_string(length=12, allowed_chars="abcd_"),
            query="select 1 from yo;",
            path="/home/yolo",
            columns=["un"],
        )
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:update_configuration", args=(configuration.pk,)),
                                        {"name": new_name,
                                         "inventory_interval": 863,
                                         "file_categories": [file_category.pk],
                                         "automatic_table_constructions": [atc.pk]},
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, new_name)
        configuration = response.context["object"]
        self.assertEqual(configuration.name, new_name)
        self.assertEqual(configuration.inventory_interval, 863)
        self.assertEqual(configuration.options, {})
        payload, metadata = assert_audit_event(self, post_event, "updated", configuration, prev_value=prev_value)
        self.assertEqual(payload["object"]["new_value"]["inventory_interval"], 863)
        self.assertEqual(payload["object"]["prev_value"]["file_categories"], [])
        self.assertEqual(payload["object"]["new_value"]["file_categories"],
                         [{"pk": file_category.pk, "name": file_category.name}])
        self.assertEqual(payload["object"]["new_value"]["automatic_table_constructions"],
                         [{"pk": atc.pk, "name": atc.name}])
        self.assertEqual(metadata["objects"], {"osquery_configuration": [str(configuration.pk)]})

    # configuration list

    def test_configuration_list_redirect(self):
        self.login_redirect("configurations")

    def test_configuration_list_permission_denied(self):
        self.login()
        response = self.client.get(reverse("osquery:configurations"))
        self.assertEqual(response.status_code, 403)

    def test_configuration_list(self):
        configuration = self._force_configuration()
        self.login("osquery.view_configuration")
        response = self.client.get(reverse("osquery:configurations"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_list.html")
        self.assertIn(configuration, response.context["object_list"])
        self.assertContains(response, configuration.name)

    # configuration

    def test_configuration_add_pack_link(self):
        configuration = self._force_configuration()
        self._force_pack()
        self.login("osquery.view_configuration", "osquery.change_configuration")
        response = self.client.get(reverse("osquery:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertContains(response, reverse("osquery:add_configuration_pack", args=(configuration.pk,)))

    def test_configuration_no_add_pack_link(self):
        configuration = self._force_configuration()
        self._force_pack()
        self.login("osquery.view_configuration")
        response = self.client.get(reverse("osquery:configuration", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertNotContains(response, reverse("osquery:add_configuration_pack", args=(configuration.pk,)))

    # add configuration pack

    def test_add_configuration_pack_redirect(self):
        configuration = self._force_configuration()
        self.login_redirect("add_configuration_pack", configuration.pk)

    def test_add_configuration_pack_permission_denied(self):
        configuration = self._force_configuration()
        self.login()
        response = self.client.get(reverse("osquery:add_configuration_pack", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_add_configuration_pack_get(self):
        configuration = self._force_configuration()
        self.login("osquery.change_configuration")
        response = self.client.get(reverse("osquery:add_configuration_pack", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_form.html")
        self.assertEqual(response.context["configuration"], configuration)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_add_configuration_pack_post(self, post_event):
        configuration = self._force_configuration()
        pack = self._force_pack()
        self.login("osquery.change_configuration", "osquery.view_configuration")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("osquery:add_configuration_pack", args=(configuration.pk,)),
                {"pack": pack.pk},
                follow=True
            )
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["configuration"], configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 1)
        configuration_pack = configuration_packs.first()
        self.assertEqual(configuration_pack.configuration, configuration)
        self.assertEqual(configuration_pack.pack, pack)
        self.assertEqual(configuration_pack.tags.count(), 0)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {"action": "created",
             "object": {
                 "model": "osquery.configurationpack",
                 "pk": str(configuration_pack.pk),
                 "new_value": {
                     "pk": configuration_pack.pk,
                     "configuration": {"pk": configuration.pk, "name": configuration.name},
                     "pack": {"pk": pack.pk, "slug": pack.slug},
                     "tags": [],
                     "excluded_tags": [],
                 }
              }}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"],
                         {"osquery_configuration_pack": [str(configuration_pack.pk)],
                          "osquery_configuration": [str(configuration.pk)],
                          "osquery_pack": [str(pack.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["osquery", "zentral"])

    # update configuration pack

    def test_update_configuration_pack_redirect(self):
        configuration_pack = self._force_configuration_pack()
        self.login_redirect("update_configuration_pack", configuration_pack.configuration.pk, configuration_pack.pk)

    def test_update_configuration_pack_permission_denied(self):
        configuration_pack = self._force_configuration_pack()
        self.login()
        response = self.client.get(reverse("osquery:update_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 403)

    def test_update_configuration_pack_get(self):
        configuration_pack = self._force_configuration_pack()
        self.login("osquery.change_configuration")
        response = self.client.get(reverse("osquery:update_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_form.html")
        self.assertEqual(response.context["configuration"], configuration_pack.configuration)
        self.assertEqual(response.context["object"], configuration_pack)

    def test_update_configuration_pack_same_tag_post_error(self):
        configuration_pack = self._force_configuration_pack()
        self.login("osquery.change_configuration", "osquery.view_configuration")
        tag = Tag.objects.create(name=get_random_string(12))
        response = self.client.post(
            reverse("osquery:update_configuration_pack",
                    args=(configuration_pack.configuration.pk, configuration_pack.pk)),
            {"pack": configuration_pack.pack.pk,
             "tags": [tag.pk],
             "excluded_tags": [tag.pk]},
            follow=True
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_form.html")
        self.assertFormError(
            response.context["form"], "tags",
            f"'{tag.name}' cannot be both included and excluded"
        )
        self.assertFormError(
            response.context["form"], "excluded_tags",
            f"'{tag.name}' cannot be both included and excluded"
        )

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_configuration_pack_post(self, post_event):
        configuration_pack = self._force_configuration_pack()
        prev_value = configuration_pack.serialize_for_event()
        self.login("osquery.change_configuration", "osquery.view_configuration")
        tag = Tag.objects.create(name=get_random_string(12))
        excluded_tag = Tag.objects.create(name=get_random_string(12))
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                reverse("osquery:update_configuration_pack",
                        args=(configuration_pack.configuration.pk, configuration_pack.pk)),
                {"pack": configuration_pack.pack.pk,
                 "tags": [tag.pk],
                 "excluded_tags": [excluded_tag.pk]},
                follow=True
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration_pack.configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 1)
        resp_configuration_pack = configuration_packs.first()
        self.assertEqual(resp_configuration_pack, configuration_pack)
        self.assertEqual(resp_configuration_pack.pack, configuration_pack.pack)
        self.assertEqual(list(resp_configuration_pack.tags.all()), [tag])
        self.assertEqual(list(resp_configuration_pack.excluded_tags.all()), [excluded_tag])
        self.assertContains(response, tag.name)
        payload, metadata = assert_audit_event(self, post_event, "updated", resp_configuration_pack,
                                               prev_value=prev_value)
        self.assertEqual(payload["object"]["prev_value"]["tags"], [])
        self.assertEqual(payload["object"]["new_value"]["tags"], [{"pk": tag.pk, "name": tag.name}])
        self.assertEqual(payload["object"]["new_value"]["excluded_tags"],
                         [{"pk": excluded_tag.pk, "name": excluded_tag.name}])
        self.assertEqual(metadata["objects"],
                         {"osquery_configuration_pack": [str(configuration_pack.pk)],
                          "osquery_configuration": [str(configuration_pack.configuration.pk)],
                          "osquery_pack": [str(configuration_pack.pack.pk)]})

    # remove configuration pack

    def test_remove_configuration_pack_redirect(self):
        configuration_pack = self._force_configuration_pack()
        self.login_redirect("remove_configuration_pack", configuration_pack.configuration.pk, configuration_pack.pk)

    def test_remove_configuration_pack_permission_denied(self):
        configuration_pack = self._force_configuration_pack()
        self.login()
        response = self.client.get(reverse("osquery:remove_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 403)

    def test_remove_configuration_pack_get(self):
        configuration_pack = self._force_configuration_pack()
        self.login("osquery.change_configuration")
        response = self.client.get(reverse("osquery:remove_configuration_pack",
                                           args=(configuration_pack.configuration.pk, configuration_pack.pk)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "osquery/configurationpack_confirm_delete.html")
        self.assertEqual(response.context["object"], configuration_pack)

    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_remove_configuration_pack_post(self, post_event):
        configuration_pack = self._force_configuration_pack()
        prev_value = configuration_pack.serialize_for_event()
        self.login("osquery.change_configuration", "osquery.view_configuration")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("osquery:remove_configuration_pack",
                                                args=(configuration_pack.configuration.pk, configuration_pack.pk)),
                                        follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(callbacks), 1)
        self.assertTemplateUsed(response, "osquery/configuration_detail.html")
        self.assertEqual(response.context["object"], configuration_pack.configuration)
        configuration_packs = response.context["configuration_packs"]
        self.assertEqual(configuration_packs.count(), 0)
        _, metadata = assert_audit_event(self, post_event, "deleted", configuration_pack, prev_value=prev_value)
        self.assertEqual(metadata["objects"],
                         {"osquery_configuration_pack": [str(configuration_pack.pk)],
                          "osquery_configuration": [str(configuration_pack.configuration.pk)],
                          "osquery_pack": [str(configuration_pack.pack.pk)]})
