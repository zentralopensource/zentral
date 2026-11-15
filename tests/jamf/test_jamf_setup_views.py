from unittest.mock import patch

import requests
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.choices import offered
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import Tag, Taxonomy
from zentral.contrib.inventory.pbac import (create_tag_action, locked_rows, refused_taxonomies_for_tag_creation_later,
                                            tag_any_machine_action)
from zentral.contrib.jamf.models import JamfInstance, TagConfig
from zentral.contrib.jamf.api_client import APIClientError


class JamfSetupViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "jamf"

    # utility methods

    def _force_jamf_instance(self, bearer_token_authentication=False):
        jamf_instance = JamfInstance.objects.create(
            host="{}.example.com".format(get_random_string(12)),
            port=443,
            path="/JSSResource",
            user=get_random_string(12),
            bearer_token_authentication=bearer_token_authentication,
        )
        jamf_instance.set_password(get_random_string(12))
        super(JamfInstance, jamf_instance).save()
        return jamf_instance

    def _force_tag_config(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        return TagConfig.objects.create(instance=jamf_instance,
                                        source="GROUP",
                                        taxonomy=t,
                                        regex=r"^YOLOFOMO: (.*)$",
                                        replacement=r"\1")

    # jamf index

    def test_jamf_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("jamf:index"))
        self.assertEqual(response.status_code, 403)

    def test_jamf_index(self):
        self.login("jamf.view_jamfinstance")
        jamf_instance = self._force_jamf_instance()
        response = self.client.get(reverse("jamf:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/index.html")
        self.assertContains(response, jamf_instance.host)

    def test_jamf_index_no_list(self):
        self.login("jamf.view_tagconfig")
        jamf_instance = self._force_jamf_instance()
        response = self.client.get(reverse("jamf:index"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/index.html")
        self.assertNotContains(response, jamf_instance.host)

    # jamf instances

    def test_jamf_instances_permission_denied(self):
        self.login()
        response = self.client.get(reverse("jamf:jamf_instances"))
        self.assertEqual(response.status_code, 403)

    def test_jamf_instances_view(self):
        self.login("jamf.view_jamfinstance")
        response = self.client.get(reverse("jamf:jamf_instances"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_list.html")
        self.assertContains(response, "Instances (0)")

    # create jamf instance

    def test_create_jamf_instance_permission_denied(self):
        self.login()
        response = self.client.get(reverse("jamf:create_jamf_instance"))
        self.assertEqual(response.status_code, 403)

    def test_create_jamf_instance_get(self):
        self.login("jamf.add_jamfinstance")
        response = self.client.get(reverse("jamf:create_jamf_instance"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_form.html")
        self.assertContains(response, "Create Instance")

    def test_create_jamf_instance_post(self):
        self.login("jamf.add_jamfinstance", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        password = get_random_string(12)
        response = self.client.post(reverse("jamf:create_jamf_instance"),
                                    {"host": "yo.example.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": password,
                                     "inventory_apps_shard": 86,
                                     "inventory_extension_attributes": "un, deux trois",
                                     "principal_user_uid_extension_attribute": "UIDUIDUID",
                                     "principal_user_pn_extension_attribute": "PNPNPN",
                                     "principal_user_dn_extension_attribute": "DNDNDN",
                                     "checkin_heartbeat_timeout": 601,
                                     "inventory_completed_heartbeat_timeout": 5432},
                                    follow=True)
        self.assertEqual(response.template_name, ["jamf/jamfinstance_detail.html"])
        self.assertContains(response, "Tag configs (0)")
        jamf_instance = response.context["object"]
        self.assertEqual(jamf_instance.version, 0)
        self.assertEqual(jamf_instance.get_password(), password)
        self.assertEqual(sorted(jamf_instance.inventory_extension_attributes), ["deux trois", "un"])
        self.assertEqual(jamf_instance.principal_user_uid_extension_attribute, "UIDUIDUID")
        self.assertEqual(jamf_instance.principal_user_pn_extension_attribute, "PNPNPN")
        self.assertEqual(jamf_instance.principal_user_dn_extension_attribute, "DNDNDN")
        self.assertContains(response, "https://yo.example.com:8443/JSSResource")
        self.assertContains(response, "godzilla")
        self.assertContains(response, "UIDUIDUID")
        self.assertContains(response, "PNPNPN")
        self.assertContains(response, "DNDNDN")
        self.assertNotContains(response, password)

    def test_create_jamf_instance_pu_missing_uid_pn(self):
        self.login("jamf.add_jamfinstance", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:create_jamf_instance"),
                                    {"host": "yo.example.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd",
                                     "inventory_apps_shard": 86,
                                     "inventory_extension_attributes": "un, deux trois",
                                     "principal_user_dn_extension_attribute": "DN",
                                     "checkin_heartbeat_timeout": 601,
                                     "inventory_completed_heartbeat_timeout": 5432},
                                    follow=True)
        self.assertEqual(response.template_name, ["jamf/jamfinstance_form.html"])
        self.assertFormError(response.context["form"], "principal_user_uid_extension_attribute",
                             "This field is required to collect the principal user information")
        self.assertFormError(response.context["form"], "principal_user_pn_extension_attribute",
                             "This field is required to collect the principal user information")

    # delete jamf instance

    def test_delete_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self.login()
        response = self.client.get(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_jamf_instance_get(self):
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.delete_jamfinstance")
        response = self.client.get(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)))
        self.assertContains(response, "Delete Instance")

    @patch("zentral.contrib.jamf.api_client.APIClient.cleanup")
    def test_delete_jamf_instance_post_cleanup_ok(self, cleanup):
        cleanup.return_value = None
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.delete_jamfinstance", "jamf.view_jamfinstance")
        response = self.client.post(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        cleanup.assert_called_once_with()
        self.assertTemplateUsed(response, "jamf/jamfinstance_list.html")
        self.assertContains(response, "Removed webhooks configuration on")
        self.assertEqual(JamfInstance.objects.filter(pk=jamf_instance.pk).count(), 0)

    @patch("zentral.contrib.jamf.api_client.APIClient.cleanup")
    def test_delete_jamf_instance_post_failed_cleanup(self, cleanup):
        cleanup.side_effect = APIClientError("Boom!")
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.delete_jamfinstance", "jamf.view_jamfinstance")
        response = self.client.post(reverse("jamf:delete_jamf_instance", args=(jamf_instance.pk,)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        cleanup.assert_called_once_with()
        self.assertTemplateUsed(response, "jamf/jamfinstance_list.html")
        self.assertContains(response, "Could not remove webhooks configuration on")
        self.assertEqual(JamfInstance.objects.filter(pk=jamf_instance.pk).count(), 0)

    # setup jamf instance

    def test_setup_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self.login()
        response = self.client.get(reverse("jamf:setup_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.contrib.jamf.api_client.requests.Session.post")
    def test_setup_jamf_instance_token_read_timeout(self, session_post):
        session_post.side_effect = requests.exceptions.ReadTimeout("read timeout")
        jamf_instance = self._force_jamf_instance(bearer_token_authentication=True)
        self.login("jamf.change_jamfinstance", "jamf.view_jamfinstance")
        with self.assertLogs("zentral.contrib.jamf.views", level="ERROR"):
            response = self.client.get(reverse("jamf:setup_jamf_instance", args=(jamf_instance.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "Could not setup webhooks on")
        session_post.assert_called_once()

    # update jamf instance

    def test_update_jamf_instance_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self.login()
        response = self.client.get(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_jamf_instance_get(self):
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.change_jamfinstance")
        response = self.client.get(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)))
        self.assertContains(response, "Update Instance")
        self.assertContains(response, jamf_instance.get_password())

    def test_update_jamf_instance_post(self):
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.change_jamfinstance", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:update_jamf_instance", args=(jamf_instance.pk,)),
                                    {"host": "yo.example2.com",
                                     "port": 8443,
                                     "path": "/JSSResource",
                                     "user": "godzilla",
                                     "password": "pwd1234",
                                     "inventory_apps_shard": 12,
                                     "checkin_heartbeat_timeout": 601,
                                     "inventory_completed_heartbeat_timeout": 5432},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "Tag configs (0)")
        self.assertContains(response, "https://yo.example2.com:8443/JSSResource")
        jamf_instance2 = response.context["object"]
        self.assertEqual(jamf_instance, jamf_instance2)
        self.assertEqual(jamf_instance2.version, 1)
        self.assertEqual(jamf_instance2.inventory_apps_shard, 12)
        self.assertEqual(jamf_instance2.checkin_heartbeat_timeout, 601)
        self.assertEqual(jamf_instance2.inventory_completed_heartbeat_timeout, 5432)
        self.assertEqual(jamf_instance2.get_password(), "pwd1234")

    # create tag config

    def test_create_tag_config_permission_denied(self):
        jamf_instance = self._force_jamf_instance()
        self.login()
        response = self.client.get(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_create_tag_config_permission_get(self):
        jamf_instance = self._force_jamf_instance()
        self.login("jamf.add_tagconfig")
        response = self.client.get(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "jamf/tagconfig_form.html")

    def test_create_tag_config(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        regex = r"^YOLOFOMO: (.*)$"
        self.login("jamf.add_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig",
                   create_tag_action, tag_any_machine_action)
        response = self.client.post(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)),
                                    {"source": "GROUP",
                                     "taxonomy": t.pk,
                                     "regex": regex,
                                     "replacement": r"\1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "Tag config (1)")
        self.assertContains(response, t.name)

    def test_create_tag_config_error(self):
        jamf_instance = self._force_jamf_instance()
        t, _ = Taxonomy.objects.get_or_create(name=get_random_string(34))
        regex = r"^YOLOFOMO: ("
        self.login("jamf.add_tagconfig")
        response = self.client.post(reverse("jamf:create_tag_config", args=(jamf_instance.pk,)),
                                    {"source": "GROUP",
                                     "taxonomy": t.pk,
                                     "regex": regex,
                                     "replacement": r"\1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/tagconfig_form.html")
        self.assertContains(response, "Not a valid regex")

    # update tag config

    def test_update_tag_config_permission_denied(self):
        tag_config = self._force_tag_config()
        self.login()
        response = self.client.get(reverse("jamf:create_tag_config", args=(tag_config.instance.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_tag_config(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self.login("jamf.change_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig",
                   create_tag_action, tag_any_machine_action)
        response = self.client.post(reverse("jamf:update_tag_config", args=(jamf_instance.pk, tag_config.pk)),
                                    {"source": "GROUP",
                                     "taxonomy": tag_config.taxonomy.pk,
                                     "regex": tag_config.regex,
                                     "replacement": r"haha: \1"},
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "Tag config (1)")
        self.assertContains(response, "haha")

    # tag config: createTag on the taxonomy, and tagAnyMachine on each of its tags

    def _tag_actions_policy(self, *statements):
        Policy.objects.update_or_create(
            name="Tests tag actions",
            defaults={"source": "".join(
                f'{effect} (principal in Role::"{self.group.pk}", action == Inventory::Action::"{action_id}", '
                f'{scope});\n'
                for effect, action_id, scope in statements
            )}
        )

    def _post_tag_config(self, taxonomy_pk, tag_config=None):
        self.client.force_login(self.user)
        if tag_config is None:
            url = reverse("jamf:create_tag_config", args=(self._force_jamf_instance().pk,))
        else:
            url = reverse("jamf:update_tag_config", args=(tag_config.instance.pk, tag_config.pk))
        return self.client.post(url, {"source": "GROUP", "taxonomy": taxonomy_pk,
                                      "regex": r"^YOLOFOMO: (.*)$", "replacement": r"\1"})

    def _assert_taxonomy_refused(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.context["form"].errors,
            {"taxonomy": ["Select a valid choice. That choice is not one of the available choices."]}
        )

    def test_tag_config_taxonomy_without_the_actions(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig")
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._post_tag_config(taxonomy.pk)
        self._assert_taxonomy_refused(response)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"createTag" Inventory::Taxonomy::"{taxonomy.pk}"', cm.output[0])
        self.assertEqual(TagConfig.objects.count(), 0)

    def test_tag_config_unknown_taxonomy(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        taxonomy_pk = taxonomy.pk
        taxonomy.delete()
        self.set_permissions("jamf.add_tagconfig", create_tag_action, tag_any_machine_action)
        with self.assertNoLogs("zentral.pbac.utils", level="WARNING"):
            response = self._post_tag_config(taxonomy_pk)
        self._assert_taxonomy_refused(response)

    def test_tag_config_taxonomy_without_tags_create_tag_alone(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig", create_tag_action)
        self.assertEqual(self._post_tag_config(taxonomy.pk).status_code, 302)
        self.assertEqual(TagConfig.objects.get().taxonomy, taxonomy)

    def test_tag_config_taxonomy_with_tags_create_tag_alone(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig", create_tag_action)
        with self.assertLogs("zentral.pbac.utils", level="WARNING") as cm:
            response = self._post_tag_config(taxonomy.pk)
        self._assert_taxonomy_refused(response)
        self.assertEqual(len(cm.output), 1)
        self.assertIn(f'Inventory::Action::"tagAnyMachine" Inventory::Tag::"{tag.pk}"', cm.output[0])

    def test_tag_config_taxonomy_with_tags_tag_any_machine_alone(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig", tag_any_machine_action)
        self._assert_taxonomy_refused(self._post_tag_config(taxonomy.pk))

    def test_tag_config_taxonomy_with_tags_the_two_actions(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig", create_tag_action, tag_any_machine_action)
        self.assertEqual(self._post_tag_config(taxonomy.pk).status_code, 302)

    def test_tag_config_taxonomy_with_one_refused_tag(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        other_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Tag.objects.create(taxonomy=other_taxonomy, name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig", create_tag_action, tag_any_machine_action)
        self._tag_actions_policy(("forbid", "tagAnyMachine", f'resource == Inventory::Tag::"{tag.pk}"'))
        self._assert_taxonomy_refused(self._post_tag_config(taxonomy.pk))
        self.assertEqual(self._post_tag_config(other_taxonomy.pk).status_code, 302)

    def test_tag_config_create_tag_on_another_resource(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        other_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_permissions("jamf.add_tagconfig")
        for scope in ('resource == System::"root"', f'resource == Inventory::Taxonomy::"{other_taxonomy.pk}"'):
            self._tag_actions_policy(("permit", "createTag", scope))
            self._assert_taxonomy_refused(self._post_tag_config(taxonomy.pk))
        self.assertEqual(self._post_tag_config(other_taxonomy.pk).status_code, 302)

    def test_tag_config_update_stored_taxonomy_refused(self):
        tag_config = self._force_tag_config()
        other_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_permissions("jamf.change_tagconfig")
        self._tag_actions_policy(("permit", "createTag", f'resource == Inventory::Taxonomy::"{other_taxonomy.pk}"'))
        self.client.force_login(self.user)
        response = self.client.get(reverse("jamf:update_tag_config",
                                           args=(tag_config.instance.pk, tag_config.pk)))
        self.assertEqual(offered(response.context["form"].fields["taxonomy"]), [other_taxonomy])
        # each save is decided, also a save that keeps the taxonomy
        self._assert_taxonomy_refused(self._post_tag_config(tag_config.taxonomy.pk, tag_config))
        self.assertEqual(self._post_tag_config(other_taxonomy.pk, tag_config).status_code, 302)
        tag_config.refresh_from_db()
        self.assertEqual(tag_config.taxonomy, other_taxonomy)

    def test_tag_config_decision_locks_and_reads_again(self):
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        # a taxonomy that the form read, and that a delete removed since
        deleted_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        Taxonomy.objects.filter(pk=deleted_taxonomy.pk).delete()
        self.set_permissions(create_tag_action, tag_any_machine_action)
        with CaptureQueriesContext(connection) as ctx:
            refused = refused_taxonomies_for_tag_creation_later(None, User.objects.get(pk=self.user.pk),
                                                                [taxonomy, deleted_taxonomy])
        self.assertEqual(refused, {deleted_taxonomy.pk})
        lock_queries = [query["sql"] for query in ctx.captured_queries if "FOR " in query["sql"]]
        self.assertEqual([query.split('"')[3] for query in lock_queries],
                         ["inventory_taxonomy", "inventory_tag", "inventory_taxonomy"])
        self.assertTrue(all(query.endswith(" FOR SHARE") for query in lock_queries))

    def test_tag_config_decision_one_batch_for_the_taxonomies(self):
        taxonomies = []
        for _ in range(2):
            taxonomy = Taxonomy.objects.create(name=get_random_string(12))
            Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
            taxonomies.append(taxonomy)
        self.set_permissions(create_tag_action, tag_any_machine_action)
        user = User.objects.get(pk=self.user.pk)
        refused_taxonomies_for_tag_creation_later(None, user, taxonomies)  # warm up the process-level caches
        query_counts = []
        for count in (1, 2):
            with CaptureQueriesContext(connection) as ctx:
                self.assertEqual(refused_taxonomies_for_tag_creation_later(None, user, taxonomies[:count]), set())
            query_counts.append(len(ctx.captured_queries))
        self.assertEqual(query_counts[0], query_counts[1])

    def test_tag_config_decision_tag_moved_to_another_taxonomy(self):
        # a tag that a move took out of the taxonomy before the lock is not decided with it
        taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        tag = Tag.objects.create(taxonomy=taxonomy, name=get_random_string(12))
        other_taxonomy = Taxonomy.objects.create(name=get_random_string(12))
        self.set_permissions(create_tag_action, tag_any_machine_action)

        def move_then_lock(request_class, model, pks):
            if model is Tag:
                Tag.objects.filter(pk=tag.pk).update(taxonomy=other_taxonomy)
            return locked_rows(request_class, model, pks)

        with patch("zentral.contrib.inventory.pbac.locked_rows", side_effect=move_then_lock):
            with patch("zentral.contrib.inventory.pbac.TagAnyMachineRequest") as tag_any_machine_request:
                refused = refused_taxonomies_for_tag_creation_later(None, User.objects.get(pk=self.user.pk),
                                                                    [taxonomy])
        self.assertEqual(refused, set())
        tag_any_machine_request.assert_not_called()

    # delete tag config

    def test_delete_tag_config_permission_denied(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self.login()
        response = self.client.get(reverse("jamf:delete_tag_config", args=(jamf_instance.pk, tag_config.pk)))
        self.assertEqual(response.status_code, 403)

    def test_delete_tag_config(self):
        tag_config = self._force_tag_config()
        jamf_instance = tag_config.instance
        self.login("jamf.delete_tagconfig", "jamf.view_jamfinstance", "jamf.view_tagconfig")
        response = self.client.post(reverse("jamf:delete_tag_config", args=(jamf_instance.pk, tag_config.pk)),
                                    follow=True)
        self.assertTemplateUsed(response, "jamf/jamfinstance_detail.html")
        self.assertContains(response, "Tag configs (0)")
