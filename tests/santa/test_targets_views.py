from datetime import datetime, timedelta
from functools import reduce
import operator
from unittest.mock import patch
from django.contrib.auth.models import Group, Permission
from django.db.models import Q
from django.urls import reverse
from django.test import TestCase, override_settings
from django.utils.crypto import get_random_string
from accounts.models import User
from zentral.contrib.inventory.models import Source, File
from zentral.contrib.santa.models import Target, TargetCounter, TargetState
from zentral.core.stores.conf import frontend_store
from .utils import add_file_to_test_class, force_ballot, force_configuration, force_realm_user, new_sha256


@override_settings(STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage')
class SantaSetupViewsTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])
        # file tree
        add_file_to_test_class(cls)

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

    # targets

    def test_targets_redirect(self):
        self._login_redirect(reverse("santa:targets"))

    def test_targets_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:targets"))
        self.assertEqual(response.status_code, 403)

    def test_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (7)")
        self.assertContains(response, self.cdhash)
        self.assertContains(response, self.file_sha256)
        self.assertContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertContains(response, self.file_signing_id)
        self.assertContains(response, self.bundle_sha256)
        self.assertContains(response, self.metabundle_sha256)

    def test_bad_target_identifier_no_url(self):
        # create bad CDHASH File & Target
        bad_cdhash_identifier = ""
        File.objects.create(
            source=Source.objects.get(module="zentral.contrib.santa", name="Santa events"),
            sha_256=new_sha256(),
            cdhash=bad_cdhash_identifier
        )
        Target.objects.create(type=Target.Type.CDHASH, identifier=bad_cdhash_identifier)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"))
        for target in response.context["targets"]:
            if target["target_type"] == Target.Type.CDHASH and target["identifier"] == bad_cdhash_identifier:
                self.assertNotIn("url", target)
            else:
                self.assertTrue(isinstance(target["url"], str))

    def test_binary_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.BINARY})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_cdhash_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.CDHASH})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_certificate_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.CERTIFICATE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_team_id_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.TEAM_ID})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_signing_id_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.SIGNING_ID})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertContains(response, self.file_team_id)
        self.assertContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_bundle_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.BUNDLE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertNotContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertContains(response, self.bundle_sha256)
        self.assertNotContains(response, self.metabundle_sha256)

    def test_metabundle_targets(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_type": Target.Type.METABUNDLE})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        self.assertNotContains(response, self.cdhash)
        self.assertNotContains(response, self.file_sha256)
        self.assertNotContains(response, self.file_cert_sha256)
        self.assertNotContains(response, self.file_team_id)
        self.assertNotContains(response, self.file_signing_id)
        self.assertNotContains(response, self.bundle_sha256)
        self.assertContains(response, self.metabundle_sha256)

    def test_search_targets_empty_results(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"q": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("santa:targets") + '">all the items')

    def test_search_target_file_identifier(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"q": self.file_sha256})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    def test_search_target_state(self):
        TargetState.objects.create(
            configuration=force_configuration(),
            target=self.bundle_target,
            flagged=True,
            state=TargetState.State.GLOBALLY_ALLOWLISTED,
            score=100,
        )
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"target_state": TargetState.State.GLOBALLY_ALLOWLISTED})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.bundle_sha256)

    def test_search_target_last_seen(self):
        TargetCounter.objects.exclude(
            target=self.file_target
        ).update(updated_at=datetime.utcnow() - timedelta(days=100))
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"),
                                   {"last_seen_days": 3})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    def test_search_target_configuration_no_link(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (0)")
        self.assertEqual(len(response.context["targets"]), 0)

    def test_search_target_configuration_via_target_state(self):
        configuration = force_configuration()
        TargetState.objects.create(
            configuration=configuration,
            target=self.file_target,
            flagged=True,
            state=TargetState.State.GLOBALLY_ALLOWLISTED,
            score=100,
        )
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)
        self.assertEqual(targets[0]["blocked_count"], 0)
        self.assertEqual(targets[0]["executed_count"], 0)
        self.assertEqual(targets[0]["collected_count"], 0)

    def test_search_target_configuration_via_target_counter(self):
        configuration = force_configuration()
        TargetCounter.objects.create(
            configuration=configuration,
            target=self.file_target,
            blocked_count=1,
            executed_count=2,
            collected_count=3,
        )
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"configuration": configuration.pk})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)
        self.assertEqual(targets[0]["blocked_count"], 1)
        self.assertEqual(targets[0]["executed_count"], 2)
        self.assertEqual(targets[0]["collected_count"], 3)

    def test_search_target_has_yes_votes_no_result(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"has_yes_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (0)")
        self.assertEqual(len(response.context["targets"]), 0)

    def test_search_target_has_no_votes_no_result(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"has_no_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (0)")
        self.assertEqual(len(response.context["targets"]), 0)

    def test_search_target_has_yes_votes_different_config_no_result(self):
        self._login("santa.view_target")
        realm, realm_user = force_realm_user()
        vote_configuration = force_configuration(voting_realm=realm)
        force_ballot(self.file_target, realm_user, [(vote_configuration, True, 1)])
        search_configuration = force_configuration(voting_realm=realm)
        response = self.client.get(reverse("santa:targets"), {"configuration": search_configuration.pk,
                                                              "has_yes_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (0)")
        self.assertEqual(len(response.context["targets"]), 0)

    def test_search_target_has_no_votes_same_config_result(self):
        self._login("santa.view_target")
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_ballot(self.file_target, realm_user, [(configuration, False, 1)])
        TargetState.objects.create(
            configuration=configuration,
            target=self.file_target,
            flagged=True,
            state=TargetState.State.UNTRUSTED,
            score=-1,
        )
        response = self.client.get(reverse("santa:targets"), {"configuration": configuration.pk,
                                                              "has_no_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        targets = response.context["targets"]
        self.assertContains(response, "Target (1)")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    def test_search_target_has_yes_votes_no_config_result(self):
        self._login("santa.view_target")
        realm, realm_user = force_realm_user()
        configuration = force_configuration(voting_realm=realm)
        force_ballot(self.file_target, realm_user, [(configuration, True, 1)])
        response = self.client.get(reverse("santa:targets"), {"has_yes_votes": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    def test_search_target_todo_no_votes_all(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:targets"), {"todo": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Targets (7)")
        self.assertEqual(len(response.context["targets"]), 7)

    def test_search_target_todo_missing_one_vote_no_config(self):
        self._login("santa.view_target")
        realm, realm_user = force_realm_user(username=self.user.username)
        configuration = force_configuration(voting_realm=realm)
        # vote on all targets except the binary
        for target in Target.objects.exclude(type=Target.Type.BINARY):
            force_ballot(target, realm_user, [(configuration, True, 1)])
        response = self.client.get(reverse("santa:targets"), {"todo": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    def test_search_target_todo_missing_one_vote_same_config(self):
        self._login("santa.view_target")
        realm, realm_user = force_realm_user(username=self.user.username)
        configuration = force_configuration(voting_realm=realm)
        # vote on all targets except the binary
        for target in Target.objects.all():
            if target.type != Target.Type.BINARY:
                force_ballot(target, realm_user, [(configuration, True, 1)])
                TargetState.objects.create(
                    configuration=configuration,
                    target=target,
                    flagged=False,
                    state=TargetState.State.UNTRUSTED,
                    score=1,
                )
            else:
                TargetState.objects.create(
                    configuration=configuration,
                    target=target,
                    flagged=False,
                    state=TargetState.State.UNTRUSTED,
                    score=0,
                )
        response = self.client.get(reverse("santa:targets"), {"configuration": configuration.pk,
                                                              "todo": "on"})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/targets.html")
        self.assertContains(response, "Target (1)")
        targets = response.context["targets"]
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["identifier"], self.file_sha256)

    # binary target

    def test_binary_target_redirect(self):
        self._login_redirect(reverse("santa:binary", args=(self.file_sha256,)))

    def test_binary_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_binary_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_sha256)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_binary_target_configuration_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:binary", args=(self.file_sha256,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_binary_target_events_redirect(self):
        self._login_redirect(reverse("santa:binary_events", args=(self.file_sha256,)))

    def test_binary_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_binary_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_sha256)

    def test_fetch_binary_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))

    def test_fetch_binary_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_binary_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_binary_events", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_binary_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)))

    def test_binary_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_binary_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:binary_events_store_redirect", args=(self.file_sha256,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # bundle target

    def test_bundle_target_redirect(self):
        self._login_redirect(reverse("santa:bundle", args=(self.bundle_target.identifier,)))

    def test_bundle_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:bundle", args=(self.bundle_target.identifier,)))
        self.assertEqual(response.status_code, 403)

    def test_bundle_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:bundle", args=(self.bundle_target.identifier,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.bundle_target.identifier)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_bundle_target_configuration_add_rule_perm(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:bundle", args=(self.bundle_target.identifier,)))
        self.assertNotContains(response, "createRule")

    # metabundle target

    def test_metabundle_target_redirect(self):
        self._login_redirect(reverse("santa:metabundle", args=(self.metabundle_sha256,)))

    def test_metabundle_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:metabundle", args=(self.metabundle_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_metabundle_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:metabundle", args=(self.metabundle_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.metabundle_sha256)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_metabundle_target_configuration_add_rule_perm(self):
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:metabundle", args=(self.metabundle_sha256,)))
        self.assertNotContains(response, "createRule")

    # cdhash target

    def test_cdhash_target_redirect(self):
        self._login_redirect(reverse("santa:cdhash", args=(self.cdhash,)))

    def test_cdhash_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    def test_cdhash_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.cdhash)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_cdhash_target_configuration_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:cdhash", args=(self.cdhash,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_cdhash_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_cdhash_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.cdhash)

    def test_fetch_cdhash_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))

    def test_fetch_cdhash_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_cdhash_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_cdhash_events", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_cdhash_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)))

    def test_cdhash_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)))
        self.assertEqual(response.status_code, 403)

    def test_cdhash_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:cdhash_events_store_redirect", args=(self.cdhash,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # certificate target

    def test_certificate_target_redirect(self):
        self._login_redirect(reverse("santa:certificate", args=(self.file_cert_sha256,)))

    def test_certificate_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_certificate_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_cert_sha256)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_certificate_target_configuration_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:certificate", args=(self.file_cert_sha256,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_certificate_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_certificate_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_cert_sha256)

    def test_fetch_certificate_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))

    def test_fetch_certificate_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_certificate_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_certificate_events", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_certificate_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)))

    def test_certificate_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)))
        self.assertEqual(response.status_code, 403)

    def test_certificate_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:certificate_events_store_redirect", args=(self.file_cert_sha256,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # team ID target

    def test_team_id_target_redirect(self):
        self._login_redirect(reverse("santa:teamid", args=(self.file_team_id,)))

    def test_team_id_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    def test_team_id_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_team_id)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_team_id_target_configuration_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:teamid", args=(self.file_team_id,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_team_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_team_id_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_team_id)

    def test_fetch_team_id_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))

    def test_fetch_team_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_team_id_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_teamid_events", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_team_id_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)))

    def test_team_id_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)))
        self.assertEqual(response.status_code, 403)

    def test_team_id_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:teamid_events_store_redirect", args=(self.file_team_id,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))

    # signing ID target

    def test_signing_id_target_redirect(self):
        self._login_redirect(reverse("santa:signingid", args=(self.file_signing_id,)))

    def test_signing_id_target_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    def test_signing_id_target_configuration_no_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_detail.html")
        self.assertContains(response, self.file_signing_id)
        self.assertNotContains(response, "createRule")
        self.assertNotContains(response, configuration.name)

    def test_signing_id_target_configuration_add_rule_perm(self):
        configuration = force_configuration()
        self._login("santa.view_target", "santa.add_rule")
        response = self.client.get(reverse("santa:signingid", args=(self.file_signing_id,)))
        self.assertContains(response, "createRule")
        self.assertContains(response, configuration.name)

    def test_signing_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.get_aggregated_object_event_counts")
    def test_signing_id_target_events(self, get_aggregated_object_event_counts):
        get_aggregated_object_event_counts.return_value = {}
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/target_events.html")
        self.assertContains(response, self.file_signing_id)

    def test_fetch_signing_id_target_events_redirect(self):
        self._login_redirect(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))

    def test_fetch_signing_id_target_events_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    @patch("zentral.core.stores.backends.elasticsearch.EventStore.fetch_object_events")
    def test_fetch_signing_id_target_events(self, fetch_object_events):
        fetch_object_events.return_value = ([], None)
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:fetch_signingid_events", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "core/stores/events_events.html")

    def test_signing_id_target_store_redirect_login_redirect(self):
        self._login_redirect(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)))

    def test_signing_id_target_store_redirect_permission_denied(self):
        self._login()
        response = self.client.get(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)))
        self.assertEqual(response.status_code, 403)

    def test_signing_id_target_store_redirect(self):
        self._login("santa.view_target")
        response = self.client.get(reverse("santa:signingid_events_store_redirect", args=(self.file_signing_id,)),
                                   {"es": frontend_store.name})
        self.assertTrue(response.url.startswith("/kibana/"))
