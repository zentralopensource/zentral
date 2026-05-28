from unittest.mock import patch
from django.contrib.auth.models import Group
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.test import TestCase

from accounts.models import Policy, User
from realms.models import Realm, RealmUser
from tests.zentral_test_utils.login_case import LoginCase
from zentral.core.events.base import AuditEvent
from .utils import force_policy


class PoliciesViewsTestCase(TestCase, LoginCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        # user
        cls.user = User.objects.create_user("godzilla", "godzilla@zentral.com", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.add(cls.group)
        # realm + matching realm user (used by tests that need a remote session)
        cls.realm = Realm.objects.create(
            name=get_random_string(12),
            enabled_for_login=True,
            backend="ldap",
            username_claim="username",
            email_claim="email",
        )
        cls.realm_user = RealmUser.objects.create(
            realm=cls.realm,
            claims={"username": cls.user.username, "email": cls.user.email},
            username=cls.user.username,
            email=cls.user.email,
        )

    # LoginCase implementation

    def _get_user(self):
        return self.user

    def _get_group(self):
        return self.group

    def _get_url_namespace(self):
        return "accounts"

    def _get_realm(self):
        return self.realm

    def _get_realm_user(self):
        return self.realm_user

    def _promote_user_to_superuser(self):
        self.user.is_superuser = True
        self.user.save()

    # list

    def test_policies_redirect(self):
        self.login_redirect("policies")

    def test_policies_permission_denied(self):
        self.login()
        response = self.client.get(self.build_url("policies"))
        self.assertEqual(response.status_code, 403)

    def test_policies_no_links(self):
        p = force_policy()
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policies"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_list.html")
        self.assertContains(response, p.name)
        self.assertNotContains(response, reverse("accounts:create_policy"))
        self.assertNotContains(response, reverse("accounts:delete_policy", args=(p.pk,)))
        self.assertNotContains(response, reverse("accounts:update_policy", args=(p.pk,)))

    @patch("accounts.views.policies.PoliciesView.get_paginate_by")
    def test_policies_all_link(self, get_paginate_by):
        get_paginate_by.return_value = 1
        force_policy()
        force_policy()
        self._promote_user_to_superuser()
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policies"))
        p_first = Policy.objects.order_by("name").first()
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_list.html")
        self.assertContains(response, "Policies (3)")  # an extra policy is always created by the LoginCase
        self.assertContains(response, "page 1 of 3")
        self.assertContains(response, reverse("accounts:create_policy"))
        self.assertContains(response, p_first.name)
        self.assertContains(response, reverse("accounts:delete_policy", args=(p_first.pk,)))
        self.assertContains(response, reverse("accounts:update_policy", args=(p_first.pk,)))

    @patch("accounts.views.policies.PoliciesView.get_paginate_by")
    def test_policies_no_modify_buttons_for_non_superuser(self, get_paginate_by):
        # A non-superuser, even one who can see the list, must not see any
        # mutation buttons — those are gated on superuser + local session.
        get_paginate_by.return_value = 1
        p = force_policy()
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policies"))
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, reverse("accounts:create_policy"))
        self.assertNotContains(response, reverse("accounts:update_policy", args=(p.pk,)))
        self.assertNotContains(response, reverse("accounts:delete_policy", args=(p.pk,)))

    @patch("accounts.views.policies.PoliciesView.get_paginate_by")
    def test_policies_no_modify_buttons_for_remote_session_superuser(self, get_paginate_by):
        get_paginate_by.return_value = 1
        p = force_policy()
        self._promote_user_to_superuser()
        self.login("accounts.view_policy", realm_user=True)
        response = self.client.get(self.build_url("policies"))
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.context["request"].realm_authentication_session.is_remote)
        self.assertNotContains(response, reverse("accounts:create_policy"))
        self.assertNotContains(response, reverse("accounts:update_policy", args=(p.pk,)))
        self.assertNotContains(response, reverse("accounts:delete_policy", args=(p.pk,)))

    # create

    def test_create_policy_redirect(self):
        self.login_redirect("create_policy")

    def test_create_policy_permission_denied(self):
        # No superuser → forbidden, even for an authenticated user.
        self.login()
        response = self.client.get(self.build_url("create_policy"))
        self.assertEqual(response.status_code, 403)

    def test_create_policy_remote_session_superuser_forbidden(self):
        # Even a superuser logged in through a realm cannot author policies.
        self._promote_user_to_superuser()
        self.login(realm_user=True)
        response = self.client.get(self.build_url("create_policy"))
        self.assertEqual(response.status_code, 403)

    def test_create_policy_get(self):
        self._promote_user_to_superuser()
        self.login()
        response = self.client.get(self.build_url("create_policy"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_form.html")
        self.assertContains(response, "Create policy")

    def test_create_policy_missing_fields(self):
        self._promote_user_to_superuser()
        self.login()
        response = self.client.post(self.build_url("create_policy"), {"source": ""})
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_form.html")
        err_msg = "This field is required."
        self.assertFormError(response.context["form"], "name", err_msg)
        self.assertFormError(response.context["form"], "source", err_msg)

    def test_create_policy_invalid_source(self):
        self._promote_user_to_superuser()
        self.login()
        response = self.client.post(
            self.build_url("create_policy"),
            {"name": get_random_string(12),
             "source": "permit ("}
        )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_form.html")
        self.assertFormError(
            response.context["form"], "source",
            "Invalid CEDAR policy: unexpected end of input"
        )

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_create_policy(self, post_event, send_notification):
        self._promote_user_to_superuser()
        self.login("accounts.view_policy")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("create_policy"),
                {"name": name,
                 "description": description,
                 "source": 'permit(principal in Role::"0", action, resource);',
                 "is_active": "on"},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_detail.html")
        self.assertEqual(len(callbacks), 1)
        policy = Policy.objects.get(name=name)
        self.assertEqual(response.context["object"], policy)
        self.assertTrue(policy.is_active)
        self.assertContains(response, name)
        self.assertContains(response, description)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'created',
             'object': {'model': 'accounts.policy',
                        'new_value': {'created_at': policy.created_at,
                                      'description': description,
                                      'is_active': True,
                                      'name': name,
                                      'pk': str(policy.pk),
                                      'source': 'permit (\n'
                                                '  principal in Role::"0",\n'
                                                '  action,\n'
                                                '  resource\n'
                                                ');\n',
                                      'type': Policy.Type.CEDAR,
                                      'updated_at': policy.updated_at},
                        'pk': str(policy.pk)}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_policy": [str(policy.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
        send_notification.assert_called_once_with("policies.change")

    # view

    def test_view_policy_login_redirect(self):
        p = force_policy()
        self.login_redirect("policy", p.pk)

    def test_view_policy_permission_denied(self):
        p = force_policy()
        self.login()
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertEqual(response.status_code, 403)

    def test_view_policy_no_links(self):
        p = force_policy()
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_detail.html")
        self.assertContains(response, p.name)
        self.assertContains(response, p.description)
        self.assertNotContains(response, self.build_url("update_policy", p.pk))
        self.assertNotContains(response, self.build_url("delete_policy", p.pk))

    def test_view_policy_all_links(self):
        p = force_policy()
        self._promote_user_to_superuser()
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_detail.html")
        self.assertContains(response, p.name)
        self.assertContains(response, p.description)
        self.assertContains(response, self.build_url("update_policy", p.pk))
        self.assertContains(response, self.build_url("delete_policy", p.pk))

    # source linkification

    def test_view_policy_links_role_principal(self):
        # The anchor must wrap the whole ``Role::"<pk>"`` reference, not
        # just the pk. The Role's name shows up as a native title=...
        # tooltip when we can resolve the pk.
        role = Group.objects.create(name="ops")
        p = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal in Role::"{role.pk}", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(
            response,
            f'<a href="{reverse("accounts:group", args=[role.pk])}" '
            f'title="ops">Role::&quot;{role.pk}&quot;</a>',
            html=False,
        )

    def test_view_policy_escapes_tooltip_when_principal_name_has_quotes(self):
        # Group names are operator-controlled and can contain anything
        # — make sure the title= attribute is HTML-escaped so a name
        # like ``yolo"fomo`` can't break out of the attribute and
        # inject arbitrary markup.
        role = Group.objects.create(name='yolo"fomo')
        p = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal in Role::"{role.pk}", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(response, 'title="yolo&quot;fomo"')
        # The raw name with an unescaped quote must NOT appear.
        self.assertNotContains(response, 'title="yolo"fomo"')

    def test_view_policy_links_role_principal_without_tooltip_when_missing(self):
        # If the policy references a Role::"<pk>" whose Group doesn't
        # exist anymore, the link still renders but without a title=
        # attribute.
        p = Policy.objects.create(
            name=get_random_string(12),
            source='permit (principal in Role::"999999", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(
            response,
            f'<a href="{reverse("accounts:group", args=[999999])}">Role::&quot;999999&quot;</a>',
            html=False,
        )

    def test_view_policy_links_user_principal(self):
        u = User.objects.create_user("bobsmith", "bob@zentral.com", get_random_string(12))
        p = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == User::"{u.pk}", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(
            response,
            f'<a href="{reverse("accounts:user", args=[u.pk])}" '
            f'title="bobsmith">User::&quot;{u.pk}&quot;</a>',
            html=False,
        )

    def test_view_policy_links_service_account_principal(self):
        sa = User.objects.create(
            username="ci-bot", email="ci@zentral.com", is_service_account=True,
        )
        p = Policy.objects.create(
            name=get_random_string(12),
            source=f'permit (principal == ServiceAccount::"{sa.pk}", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(
            response,
            f'<a href="{reverse("accounts:user", args=[sa.pk])}" '
            f'title="ci-bot">ServiceAccount::&quot;{sa.pk}&quot;</a>',
            html=False,
        )

    def test_view_policy_does_not_link_actions_or_resources(self):
        # MDM::Action::"viewAdminPassword" should not be linked; same
        # for resource-type references. Only Role / User / ServiceAccount
        # principals get anchor tags.
        p = Policy.objects.create(
            name=get_random_string(12),
            source=(
                'permit (\n'
                '  principal,\n'
                '  action == MDM::Action::"viewAdminPassword",\n'
                '  resource == Inventory::Machine::"ABC123"\n'
                ');\n'
            ),
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        # source_html is the linkified policy text the template renders
        # inside the <pre>. The full HTML response has unrelated anchor
        # tags (navigation, breadcrumbs, ...), so we scope the
        # assertion to the rendered source string itself.
        self.assertNotIn("<a href=", response.context["source_html"])
        self.assertIn('MDM::Action::&quot;viewAdminPassword&quot;', response.context["source_html"])
        self.assertIn('Inventory::Machine::&quot;ABC123&quot;', response.context["source_html"])

    def test_view_policy_non_numeric_principal_id_not_linked(self):
        # A Role::"<provisioning-uid>" reference that wasn't substituted
        # to a numeric pk shouldn't produce a broken /accounts/roles/X/
        # link — render as plain text instead.
        p = Policy.objects.create(
            name=get_random_string(12),
            source='permit (principal in Role::"unresolved-uid", action, resource);\n',
        )
        self.login("accounts.view_policy")
        response = self.client.get(self.build_url("policy", p.pk))
        self.assertContains(response, 'Role::&quot;unresolved-uid&quot;')
        self.assertNotContains(response, 'href="/accounts/roles/unresolved-uid')

    # update

    def test_update_policy_login_redirect(self):
        p = force_policy()
        self.login_redirect("update_policy", p.pk)

    def test_update_policy_permission_denied(self):
        p = force_policy()
        self.login()
        response = self.client.get(self.build_url("update_policy", p.pk))
        self.assertEqual(response.status_code, 403)

    def test_update_policy_remote_session_superuser_forbidden(self):
        p = force_policy()
        self._promote_user_to_superuser()
        self.login(realm_user=True)
        response = self.client.get(self.build_url("update_policy", p.pk))
        self.assertEqual(response.status_code, 403)

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_update_policy(self, post_event, send_notification):
        p = force_policy()
        prev_value = p.serialize_for_event()
        self._promote_user_to_superuser()
        self.login("accounts.view_policy")
        name = get_random_string(12)
        description = get_random_string(12)
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("update_policy", p.pk),
                {"name": name,
                 "description": description,
                 "source": 'permit(principal in Role::"abc", action, resource);',
                 "is_active": ""},
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_detail.html")
        self.assertEqual(len(callbacks), 1)
        policy = Policy.objects.get(name=name)
        self.assertEqual(p, policy)
        self.assertEqual(response.context["object"], policy)
        self.assertFalse(policy.is_active)
        self.assertContains(response, name)
        self.assertContains(response, description)
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'updated',
             'object': {'model': 'accounts.policy',
                        'new_value': {'created_at': policy.created_at,
                                      'description': description,
                                      'is_active': False,
                                      'name': name,
                                      'pk': str(policy.pk),
                                      'source': 'permit (\n'
                                                '  principal in Role::"abc",\n'
                                                '  action,\n'
                                                '  resource\n'
                                                ');\n',
                                      'type': Policy.Type.CEDAR,
                                      'updated_at': policy.updated_at},
                        'pk': str(policy.pk),
                        'prev_value': prev_value}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_policy": [str(policy.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
        send_notification.assert_called_once_with("policies.change")

    # delete

    def test_delete_policy_login_redirect(self):
        p = force_policy()
        self.login_redirect("delete_policy", p.pk)

    def test_delete_policy_permission_denied(self):
        p = force_policy()
        self.login()
        response = self.client.get(self.build_url("delete_policy", p.pk))
        self.assertEqual(response.status_code, 403)

    def test_delete_policy_remote_session_superuser_forbidden(self):
        p = force_policy()
        self._promote_user_to_superuser()
        self.login(realm_user=True)
        response = self.client.get(self.build_url("delete_policy", p.pk))
        self.assertEqual(response.status_code, 403)

    @patch("base.notifier.Notifier.send_notification")
    @patch("zentral.core.queues.backends.kombu.EventQueues.post_event")
    def test_delete_policy(self, post_event, send_notification):
        p = force_policy()
        prev_value = p.serialize_for_event()
        self._promote_user_to_superuser()
        self.login("accounts.view_policy")
        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(
                self.build_url("delete_policy", p.pk),
                follow=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "accounts/policy_list.html")
        self.assertEqual(len(callbacks), 1)
        self.assertFalse(Policy.objects.filter(pk=p.pk).exists())
        self.assertEqual(len(post_event.call_args_list), 1)
        event = post_event.call_args_list[0].args[0]
        self.assertIsInstance(event, AuditEvent)
        self.assertEqual(
            event.payload,
            {'action': 'deleted',
             'object': {'model': 'accounts.policy',
                        'pk': str(p.pk),
                        'prev_value': prev_value}}
        )
        metadata = event.metadata.serialize()
        self.assertEqual(metadata["objects"], {"accounts_policy": [str(p.pk)]})
        self.assertEqual(sorted(metadata["tags"]), ["accounts", "zentral"])
        send_notification.assert_called_once_with("policies.change")
