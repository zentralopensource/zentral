from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import User
from tests.core_probes.utils import force_action
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.probes.models import ProbeSource
from zentral.utils.provisioning import provision


class ProbeViewsTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        # provision the stores
        provision()
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
        return "probes"

    # utility methods

    def _force_probe(self, event_types=None, active=True, platforms=None):
        if event_types is None:
            event_types = ["zentral_login", "zentral_logout"]
        filters = {"metadata": [{"event_types": event_types}]}
        if platforms:
            filters["inventory"] = [{"platforms": platforms}]
        return ProbeSource.objects.create(
            name=get_random_string(12),
            status=ProbeSource.ACTIVE if active else ProbeSource.INACTIVE,
            body={"filters": filters}
        )

    # create probe

    def test_create_probe_redirect(self):
        self.login_redirect("create")

    def test_create_probe_permission_denied(self):
        self.login()
        response = self.client.get(reverse("probes:create"))
        self.assertEqual(response.status_code, 403)

    def test_create_probe_get(self):
        self.login("probes.add_probesource")
        response = self.client.get(reverse("probes:create"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/form.html")
        self.assertContains(response, "Create event probe")

    def test_create_probe_error(self):
        self.login("probes.add_probesource")
        response = self.client.post(reverse("probes:create"), {})
        self.assertFormError(response.context["form"], "name", "This field is required.")

    def test_create_probe(self, **kwargs):
        name = get_random_string(12)
        self.login("probes.add_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:create"),
                                    {"name": name,
                                     "event_types": ["zentral_login",
                                                     "zentral_logout"],
                                     "event_tags": ["heartbeat"],
                                     "event_routing_keys": "un,deux"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        self.assertIn("probe", response.context)
        probe = response.context["probe"]
        self.assertIn("object", response.context)
        probe_source = response.context["object"]
        self.assertEqual(probe.name, name)
        self.assertEqual(probe_source.name, name)
        self.assertEqual(probe_source.pk, probe.pk)
        self.assertEqual(len(probe.metadata_filters), 1)
        f = probe.metadata_filters[0]
        self.assertEqual(f.event_types, {"zentral_login", "zentral_logout"})
        self.assertEqual(f.event_tags, {"heartbeat"})
        self.assertEqual(f.event_routing_keys,  {"un", "deux"})

    # update probe

    def test_update_probe_redirect(self):
        probe_source = self._force_probe()
        self.login_redirect("update", probe_source.pk)

    def test_update_probe_permission_denied(self):
        probe_source = self._force_probe()
        self.login()
        response = self.client.get(reverse("probes:update", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_update_probe_get(self):
        probe_source = self._force_probe()
        self.login("probes.change_probesource")
        response = self.client.get(reverse("probes:update", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/form.html")

    def test_update_probe_post(self):
        probe_source = self._force_probe(active=True)
        self.assertEqual(probe_source.actions.count(), 0)
        self.login("probes.change_probesource", "probes.view_probesource")
        action = force_action()
        response = self.client.post(reverse("probes:update", args=(probe_source.pk,)),
                                    {"name": probe_source.name,
                                     "status": ProbeSource.INACTIVE,
                                     "actions": [action.pk]},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(ctx_probe_source.status, ProbeSource.INACTIVE)
        self.assertEqual(ctx_probe_source.actions.count(), 1)
        self.assertEqual(ctx_probe_source.actions.first(), action)
        self.assertContains(response, action.name)

    # delete probe

    def test_delete_probe_redirect(self):
        probe_source = self._force_probe()
        self.login_redirect("delete", probe_source.pk)

    def test_delete_probe_permission_denied(self):
        probe_source = self._force_probe()
        self.login()
        response = self.client.get(reverse("probes:delete", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_delete_probe_get(self):
        probe_source = self._force_probe()
        self.login("probes.delete_probesource")
        response = self.client.get(reverse("probes:delete", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/delete.html")

    def test_delete_probe_post(self):
        probe_source = self._force_probe()
        self.login("probes.delete_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:delete", args=(probe_source.pk,)), follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/index.html")

    # clone probe

    def test_clone_probe_redirect(self):
        probe_source = self._force_probe()
        self.login_redirect("clone", probe_source.pk)

    def test_clone_probe_permission_denied(self):
        probe_source = self._force_probe()
        self.login("probes.view_probesource")
        response = self.client.get(reverse("probes:clone", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_clone_probe_get(self):
        probe_source = self._force_probe()
        self.login("probes.add_probesource")
        response = self.client.get(reverse("probes:clone", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/clone.html")
        self.assertContains(response, f"{probe_source.name} (clone)")

    def test_clone_probe_post_name_error(self):
        probe_source = self._force_probe()
        self.login("probes.add_probesource")
        response = self.client.post(
            reverse("probes:clone", args=(probe_source.pk,)),
            {"name": probe_source.name},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/clone.html")
        self.assertFormError(response.context["form"], "name", "A probe with this name already exists.")

    def test_clone_probe_post(self):
        probe_source = self._force_probe()
        self.login("probes.add_probesource", "probes.view_probesource")
        new_name = get_random_string(12)
        response = self.client.post(
            reverse("probes:clone", args=(probe_source.pk,)),
            {"name": new_name},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        self.assertContains(response, new_name)
        probe_source_2 = ProbeSource.objects.get(name=new_name)
        self.assertNotEqual(probe_source_2, probe_source)
        self.assertEqual(probe_source_2.body, probe_source.body)

    # probe events

    def test_probe_events_redirect(self):
        probe_source = self._force_probe()
        self.login_redirect("probe_events", probe_source.pk)

    def test_probe_events_permission_denied(self):
        probe_source = self._force_probe()
        self.login("probes.add_probesource")
        response = self.client.get(reverse("probes:probe_events", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 403)

    def test_probe_events(self):
        probe_source = self._force_probe()
        self.login("probes.view_probesource")
        response = self.client.get(reverse("probes:probe_events", args=(probe_source.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe_events.html")

    # add filter

    def test_add_probe_filter_redirect(self):
        probe_source = self._force_probe()
        self.login_redirect("add_filter", probe_source.pk, "inventory")

    def test_add_probe_filter_permission_denied(self):
        probe_source = self._force_probe()
        self.login()
        response = self.client.get(reverse("probes:add_filter", args=(probe_source.pk, "inventory")))
        self.assertEqual(response.status_code, 403)

    def test_add_probe_filter_get(self):
        probe_source = self._force_probe()
        self.login("probes.change_probesource")
        response = self.client.get(reverse("probes:add_filter", args=(probe_source.pk, "inventory")))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/filter_form.html")

    def test_add_probe_filter_post(self):
        probe_source = self._force_probe()
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:add_filter", args=(probe_source.pk, "inventory")),
                                    {"platforms": "LINUX"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(ctx_probe_source.body["filters"]["inventory"][0],
                         {'platforms': ['LINUX']})

    def test_add_probe_payload_filter_post(self):
        probe_source = self._force_probe()
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(
            reverse("probes:add_filter", args=(probe_source.pk, "payload")),
            {"form-INITIAL_FORMS": 1,
             "form-TOTAL_FORMS": 1,
             "form-MIN_NUM_FORMS": 1,
             "form-MAX_NUM_FORMS": 10,
             "form-0-attribute": "decision",
             "form-0-operator": "IN",
             "form-0-values": 'BLOCK_TEAMID, BLOCK_SCOPE, BLOCK_BINARY, BLOCK_SIGNINGID, BLOCK_UNKNOWN',
             "form-0-DELETE": ""},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(
            ctx_probe_source.body,
            {'filters': {'metadata': [{'event_types': ['zentral_login', 'zentral_logout']}],
             'payload': [[{'attribute': 'decision',
                           'operator': 'IN',
                           'values': ['BLOCK_TEAMID',
                                      'BLOCK_SCOPE',
                                      'BLOCK_BINARY',
                                      'BLOCK_SIGNINGID',
                                      'BLOCK_UNKNOWN']}]]}},
        )

    # update filter

    def test_update_probe_filter_redirect(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login_redirect("update_filter", probe_source.pk, "inventory", 0)

    def test_update_probe_filter_permission_denied(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login()
        response = self.client.get(reverse("probes:update_filter", args=(probe_source.pk, "inventory", 0)))
        self.assertEqual(response.status_code, 403)

    def test_update_probe_filter_get(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login("probes.change_probesource")
        response = self.client.get(reverse("probes:update_filter", args=(probe_source.pk, "inventory", 0)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/filter_form.html")

    def test_update_probe_filter_post(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:update_filter", args=(probe_source.pk, "inventory", 0)),
                                    {"platforms": "WINDOWS"},
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(ctx_probe_source.body["filters"]["inventory"][0],
                         {'platforms': ['WINDOWS']})

    def test_update_probe_payload_filter_get(self):
        probe_source = self._force_probe()
        probe_source.body["filters"]['payload'] = [
             [{'attribute': 'decision',
               'operator': 'IN',
               'values': ['BLOCK_TEAMID',
                          'HAHA,HOHO']}]
        ]
        probe_source.save()
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.get(reverse("probes:update_filter", args=(probe_source.pk, "payload", 0)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/payload_filter_form.html")

    def test_update_probe_payload_filter_post(self):
        probe_source = self._force_probe()
        probe_source.body["filters"]['payload'] = [
             [{'attribute': 'decision',
               'operator': 'IN',
               'values': ['BLOCK_TEAMID',
                          'BLOCK_SCOPE',
                          'BLOCK_BINARY',
                          'BLOCK_SIGNINGID',
                          'BLOCK_UNKNOWN']}]
        ]
        probe_source.save()
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(
            reverse("probes:update_filter", args=(probe_source.pk, "payload", 0)),
            {"form-INITIAL_FORMS": 1,
             "form-TOTAL_FORMS": 1,
             "form-MIN_NUM_FORMS": 1,
             "form-MAX_NUM_FORMS": 10,
             "form-0-attribute": "decision",
             "form-0-operator": "IN",
             "form-0-values": ["BLOCK_TEAMID"],
             "form-0-DELETE": ""},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(
            ctx_probe_source.body,
            {'filters': {'metadata': [{'event_types': ['zentral_login', 'zentral_logout']}],
             'payload': [[{'attribute': 'decision',
                           'operator': 'IN',
                           'values': ['BLOCK_TEAMID']}]]}},
        )

    # delete filter

    def test_delete_probe_filter_redirect(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login_redirect("delete_filter", probe_source.pk, "inventory", 0)

    def test_delete_probe_filter_permission_denied(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login()
        response = self.client.get(reverse("probes:delete_filter", args=(probe_source.pk, "inventory", 0)))
        self.assertEqual(response.status_code, 403)

    def test_delete_probe_filter_get(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login("probes.change_probesource")
        response = self.client.get(reverse("probes:delete_filter", args=(probe_source.pk, "inventory", 0)))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/delete_filter.html")

    def test_delete_probe_filter_post(self):
        probe_source = self._force_probe(platforms=["LINUX"])
        self.login("probes.change_probesource", "probes.view_probesource")
        response = self.client.post(reverse("probes:delete_filter", args=(probe_source.pk, "inventory", 0)),
                                    follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "probes/probe.html")
        ctx_probe_source = response.context["object"]
        self.assertEqual(ctx_probe_source, probe_source)
        self.assertEqual(ctx_probe_source.body["filters"]["inventory"], [])

    # index

    def test_index_redirect(self):
        self.login_redirect("index")

    def test_index_permission_denied(self):
        self.login()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 403)

    def test_index_search(self):
        self.login("probes.view_probesource")
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "We didn't find any item related to your search")
        probe_source = self._force_probe(active=False)
        probe_source2 = self._force_probe()
        response = self.client.get(reverse("probes:index"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, probe_source.name)
        self.assertContains(response, probe_source2.name)
        response = self.client.get(reverse("probes:index"), {"status": probe_source.status})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, probe_source.name)
        self.assertNotContains(response, probe_source2.name)
        response = self.client.get(reverse("probes:index"), {"q": probe_source.name})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, probe_source.name)
        self.assertNotContains(response, probe_source2.name)
        response = self.client.get(reverse("probes:index"), {"q": "does not exists"})
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, probe_source.name)
        self.assertNotContains(response, probe_source2.name)
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, reverse("probes:index") + '">all the items')
