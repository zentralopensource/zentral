from unittest.mock import patch

from django.db import connection
from django.contrib.auth.models import Group
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.html import escape

from accounts.models import OIDCAPITokenIssuer, Policy, User
from accounts.pbac import (get_oidc_api_token_issuer_resource, issuers_with_visible_condition,
                           with_oidc_api_token_issuer_resource_relations)
from accounts.serializers import OIDCAPITokenIssuerSerializer
from pbac.engine import ActionGroupBasename, engine
from tests.zentral_test_utils.zentral_api_test_case import ZentralAPITestCase


class OIDCAPITokenIssuerAccessTestCase(ZentralAPITestCase):
    # The view groups read the issuers. The CEL condition shows which workload to compromise: only the Admin
    # groups read it, and without them the key is absent.

    @classmethod
    def _create_issuer(cls):
        return OIDCAPITokenIssuer.objects.create(
            audience=get_random_string(12),
            cel_condition=f"claims.sub == '{get_random_string(12)}'",
            issuer_uri="https://issuer.zentral.com",
            name=get_random_string(12),
            user=cls.service_account,
        )

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        cls.issuer = cls._create_issuer()
        cls.other_issuer = cls._create_issuer()

    def _set_policy(self, action_scope, extra_source=""):
        Policy.objects.update_or_create(
            name="Tests OIDC API token issuers",
            defaults={"source": f'permit (principal in Role::"{self.group.pk}", {action_scope}, resource);\n'
                                f'{extra_source}'},
        )

    def _forbid_condition_of_the_issuer(self):
        return (f'forbid (principal, action == Accounts::Action::"viewOIDCAPITokenIssuerCondition", '
                f'resource == Accounts::OIDCAPITokenIssuer::"{self.issuer.pk}");\n')

    def _assert_condition_key(self, data, issuer, allowed):
        if allowed:
            self.assertEqual(data["cel_condition"], issuer.cel_condition)
        else:
            self.assertNotIn("cel_condition", data)

    def _assert_api(self, status_code, condition_allowed=False, other_condition_allowed=None):
        if other_condition_allowed is None:
            other_condition_allowed = condition_allowed
        if status_code == 200:
            # a hidden field is not a refusal
            with self.assertNoLogs("zentral.pbac.utils", "WARNING"):
                list_response = self.get(reverse("accounts_api:oidc_api_token_issuers"))
                response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)))
        else:
            list_response = self.get(reverse("accounts_api:oidc_api_token_issuers"))
            response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(self.issuer.pk,)))
        self.assertEqual(list_response.status_code, status_code)
        self.assertEqual(response.status_code, status_code)
        if status_code == 200:
            rows = {row["id"]: row for row in list_response.json()["results"]}
            self.assertEqual(set(rows), {str(self.issuer.pk), str(self.other_issuer.pk)})
            self._assert_condition_key(rows[str(self.issuer.pk)], self.issuer, condition_allowed)
            self._assert_condition_key(rows[str(self.other_issuer.pk)], self.other_issuer, other_condition_allowed)
            self._assert_condition_key(response.json(), self.issuer, condition_allowed)
        return response

    def _assert_console(self, allowed, condition_allowed=False):
        self.client.force_login(self.user)
        issuer_url = reverse("accounts:oidc_api_token_issuer", args=(self.service_account.pk, self.issuer.pk))
        if allowed:
            # a hidden row is not a refusal
            with self.assertNoLogs("zentral.pbac.utils", "WARNING"):
                response = self.client.get(issuer_url)
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, self.issuer.issuer_uri)
            self.assertContains(response, self.issuer.audience)
            if condition_allowed:
                self.assertContains(response, "CEL condition")
                self.assertContains(response, escape(self.issuer.cel_condition))
            else:
                self.assertNotContains(response, "CEL condition")
                self.assertNotContains(response, escape(self.issuer.cel_condition))
        else:
            response = self.client.get(issuer_url)
            self.assertEqual(response.status_code, 403)
        response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        if allowed:
            self.assertContains(response, self.issuer.name)
        else:
            self.assertNotContains(response, self.issuer.name)

    # action groups

    def _action_groups(self, *basenames):
        namespace = engine.get_namespace("Accounts")
        groups = set()
        for basename in basenames:
            groups.update((engine.get_action_group(basename, namespace), engine.get_action_group(basename)))
        return groups

    def test_view_action_groups(self):
        action = engine.get_action("viewOIDCAPITokenIssuer", engine.get_namespace("Accounts"))
        self.assertEqual(
            set(action.parents),
            self._action_groups(ActionGroupBasename.ADMIN, ActionGroupBasename.USER, ActionGroupBasename.VIEWER),
        )

    def test_view_condition_action_groups(self):
        action = engine.get_action("viewOIDCAPITokenIssuerCondition", engine.get_namespace("Accounts"))
        self.assertEqual(set(action.parents), self._action_groups(ActionGroupBasename.ADMIN))

    def test_view_condition_action_not_reachable_with_has_perm(self):
        action = engine.get_action("viewOIDCAPITokenIssuerCondition", engine.get_namespace("Accounts"))
        self.assertNotIn(action, engine.legacy_perm_actions.values())

    # roles

    def test_no_policy(self):
        self._assert_api(403)

    def test_view_user_only(self):
        self._set_policy('action == Accounts::Action::"viewUser"')
        self._assert_api(403)
        self._assert_console(False)

    def test_view_user_only_reads_no_issuer(self):
        self._set_policy('action == Accounts::Action::"viewUser"')
        self.client.force_login(self.user)
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(self.service_account.get_absolute_url())
        self.assertEqual(response.status_code, 200)
        self.assertEqual([query for query in ctx.captured_queries if "accounts_oidcapitokenissuer" in query["sql"]],
                         [])

    def test_viewer_actions(self):
        self._set_policy('action in Action::"GlobalViewerActions"')
        self._assert_api(200)
        self._assert_console(True)

    def test_user_actions(self):
        self._set_policy('action in Action::"GlobalUserActions"')
        self._assert_api(200)
        self._assert_console(True)

    def test_namespace_viewer_actions(self):
        self._set_policy('action in Accounts::Action::"ViewerActions"')
        self._assert_api(200)
        self._assert_console(True)

    def test_namespace_user_actions(self):
        self._set_policy('action in Accounts::Action::"UserActions"')
        self._assert_api(200)
        self._assert_console(True)

    def test_namespace_admin_actions(self):
        self._set_policy('action in Accounts::Action::"AdminActions"')
        self._assert_api(200, condition_allowed=True)
        self._assert_console(True, condition_allowed=True)

    def test_admin_actions(self):
        self._set_policy('action in Action::"GlobalAdminActions"')
        self._assert_api(200, condition_allowed=True)
        self._assert_console(True, condition_allowed=True)

    def test_admin_actions_forbid_on_the_issuer(self):
        self._set_policy('action in Action::"GlobalAdminActions"', self._forbid_condition_of_the_issuer())
        # one decision for each row: the other issuer keeps its condition
        self._assert_api(200, condition_allowed=False, other_condition_allowed=True)
        self._assert_console(True)

    def test_the_actions_named(self):
        self._set_policy('action in [Accounts::Action::"viewOIDCAPITokenIssuer", '
                         'Accounts::Action::"viewOIDCAPITokenIssuerCondition", Accounts::Action::"viewUser"]')
        self._assert_api(200, condition_allowed=True)
        self._assert_console(True, condition_allowed=True)

    def test_the_condition_action_alone(self):
        # the condition is an element of the issuer: without viewOIDCAPITokenIssuer, nothing is returned
        self._set_policy('action == Accounts::Action::"viewOIDCAPITokenIssuerCondition"')
        self._assert_api(403)

    def test_list_one_cedar_call(self):
        self._set_policy('action in Action::"GlobalAdminActions"')
        decisions = []
        original = engine.authorize_requests

        def authorize_requests(requests):
            requests = list(requests)
            condition_requests = [request for request in requests
                                  if request.action.id == "viewOIDCAPITokenIssuerCondition"]
            if condition_requests:
                decisions.append(condition_requests)
            return original(requests)

        with patch.object(engine, "authorize_requests", side_effect=authorize_requests):
            response = self.get(reverse("accounts_api:oidc_api_token_issuers"))
        self.assertEqual(response.status_code, 200)
        # one batch, with each row of the page
        self.assertEqual(len(decisions), 1)
        self.assertEqual({request.resource.id for request in decisions[0]},
                         {str(self.issuer.pk), str(self.other_issuer.pk)})

    # the resource: a member of its service account, with a name

    def test_condition_of_the_issuers_of_one_service_account(self):
        self._set_policy(
            'action in Action::"GlobalViewerActions"',
            f'permit (principal in Role::"{self.group.pk}", '
            f'action == Accounts::Action::"viewOIDCAPITokenIssuerCondition", '
            f'resource in ServiceAccount::"{self.service_account.pk}");\n'
        )
        self._assert_api(200, condition_allowed=True)
        other_service_account = User.objects.create(username=get_random_string(12),
                                                    email=f"{get_random_string(12)}@zentral.io",
                                                    is_service_account=True)
        foreign_issuer = OIDCAPITokenIssuer.objects.create(
            audience=get_random_string(12), cel_condition="claims.sub == 'x'",
            issuer_uri="https://issuer.zentral.com", name=get_random_string(12), user=other_service_account,
        )
        response = self.get(reverse("accounts_api:oidc_api_token_issuer", args=(foreign_issuer.pk,)))
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("cel_condition", response.json())

    def _set_one_service_account_policy(self):
        self._set_policy(
            'action in Action::"GlobalViewerActions"',
            f'permit (principal in Role::"{self.group.pk}", '
            f'action == Accounts::Action::"viewOIDCAPITokenIssuerCondition", '
            f'resource in ServiceAccount::"{self.service_account.pk}");\n'
        )

    def test_human_caller_condition_of_the_issuers_of_one_service_account(self):
        # the caller is not the parent of the resource
        self._set_one_service_account_policy()
        issuers = [self.issuer, self.other_issuer]
        self.assertEqual(issuers_with_visible_condition(self._http_request(self.user), issuers),
                         {self.issuer.pk, self.other_issuer.pk})
        self._assert_console(True, condition_allowed=True)

    def test_other_service_account_caller_condition_of_the_issuers_of_one_service_account(self):
        self._set_one_service_account_policy()
        caller = User.objects.create(username=get_random_string(12), email=f"{get_random_string(12)}@zentral.io",
                                     is_service_account=True)
        caller.groups.set([self.group])
        self.assertEqual(issuers_with_visible_condition(self._http_request(caller), [self.issuer, self.other_issuer]),
                         {self.issuer.pk, self.other_issuer.pk})

    def _create_service_account(self, *groups):
        service_account = User.objects.create(username=get_random_string(12),
                                              email=f"{get_random_string(12)}@zentral.io",
                                              is_service_account=True)
        service_account.groups.set(groups)
        return service_account

    def test_condition_of_the_issuers_of_the_accounts_of_one_role(self):
        # the parent carries the roles of the service account for each caller, not only for the account itself
        ci_role = Group.objects.create(name=get_random_string(12))
        self.service_account.groups.add(ci_role)
        foreign_issuer = OIDCAPITokenIssuer.objects.create(
            audience=get_random_string(12), cel_condition="claims.sub == 'x'",
            issuer_uri="https://issuer.zentral.com", name=get_random_string(12),
            user=self._create_service_account(),
        )
        self._set_policy(
            'action in Action::"GlobalViewerActions"',
            f'permit (principal in Role::"{self.group.pk}", '
            f'action == Accounts::Action::"viewOIDCAPITokenIssuerCondition", '
            f'resource in Role::"{ci_role.pk}");\n'
        )
        issuers = list(with_oidc_api_token_issuer_resource_relations(OIDCAPITokenIssuer.objects.all()))
        expected = {self.issuer.pk, self.other_issuer.pk}
        for caller in (User.objects.get(pk=self.service_account.pk),
                       User.objects.get(pk=self.user.pk),
                       self._create_service_account(self.group)):
            # the issuer of the account outside the role is left out
            self.assertEqual(issuers_with_visible_condition(self._http_request(caller), issuers), expected)
        self.assertIn(foreign_issuer, issuers)
        self._assert_console(True, condition_allowed=True)

    def test_list_queries_do_not_grow_with_the_rows(self):
        self._set_policy('action in Action::"GlobalAdminActions"')
        url = reverse("accounts_api:oidc_api_token_issuers")
        self.assertEqual(self.get(url).status_code, 200)  # policies cache

        def count_queries():
            with CaptureQueriesContext(connection) as ctx:
                response = self.get(url)
            self.assertEqual(response.status_code, 200)
            return len(ctx.captured_queries), len(response.json()["results"])

        queries, rows = count_queries()
        for _ in range(3):
            OIDCAPITokenIssuer.objects.create(
                audience=get_random_string(12), cel_condition="claims.sub == 'x'",
                issuer_uri="https://issuer.zentral.com", name=get_random_string(12),
                user=self._create_service_account(self.group),
            )
        more_queries, more_rows = count_queries()
        self.assertEqual(more_rows, rows + 3)
        self.assertEqual(more_queries, queries)

    def test_issuer_of_a_user_has_no_parent(self):
        # only a manual edit: Zentral gives an issuer to a service account only
        issuer = OIDCAPITokenIssuer.objects.create(
            audience=get_random_string(12), cel_condition="claims.sub == 'x'",
            issuer_uri="https://issuer.zentral.com", name=get_random_string(12), user=self.user,
        )
        self.assertEqual(get_oidc_api_token_issuer_resource(issuer).parents, [])
        self._set_policy(
            'action in Action::"GlobalViewerActions"',
            f'permit (principal in Role::"{self.group.pk}", '
            f'action == Accounts::Action::"viewOIDCAPITokenIssuerCondition", '
            f'resource in ServiceAccount::"{self.user.pk}");\n'
        )
        self.assertEqual(issuers_with_visible_condition(self._http_request(self.user), [issuer]), set())

    # the principal and the request

    def _http_request(self, user):
        request = RequestFactory().get("/")
        request.user = user
        return request

    def test_superuser_sees_the_conditions_without_policy(self):
        superuser = User.objects.create_user(get_random_string(12), f"{get_random_string(12)}@zentral.io",
                                             get_random_string(12), is_superuser=True)
        self.assertEqual(issuers_with_visible_condition(self._http_request(superuser), [self.issuer]),
                         {self.issuer.pk})

    def test_inactive_user_sees_no_condition(self):
        self._set_policy('action in Action::"GlobalAdminActions"')
        self.user.is_active = False
        self.user.save()
        user = User.objects.get(pk=self.user.pk)
        self.assertEqual(issuers_with_visible_condition(self._http_request(user), [self.issuer]), set())

    def test_no_request_no_condition(self):
        self.assertEqual(issuers_with_visible_condition(None, [self.issuer]), set())
        # a serializer used without a request leaves the condition out
        self.assertNotIn("cel_condition", OIDCAPITokenIssuerSerializer(self.issuer).data)
        self.assertNotIn("cel_condition", OIDCAPITokenIssuerSerializer([self.issuer], many=True).data[0])

    def test_list_serializer_accepts_a_manager(self):
        self._set_policy('action in Action::"GlobalAdminActions"')
        data = OIDCAPITokenIssuerSerializer(self.service_account.oidcapitokenissuer_set, many=True,
                                            context={"request": self._http_request(self.user)}).data
        self.assertEqual({row["id"]: row["cel_condition"] for row in data},
                         {str(self.issuer.pk): self.issuer.cel_condition,
                          str(self.other_issuer.pk): self.other_issuer.cel_condition})

    # fields

    def test_api_fields(self):
        self._set_policy('action in Action::"GlobalViewerActions"')
        response = self._assert_api(200)
        # no cel_condition key
        self.assertEqual(
            response.json(),
            {"id": str(self.issuer.pk),
             "user": self.service_account.pk,
             "name": self.issuer.name,
             "description": "",
             "issuer_uri": "https://issuer.zentral.com",
             "audience": self.issuer.audience,
             "max_validity": 3600,
             "created_at": self.issuer.created_at.isoformat(),
             "updated_at": self.issuer.updated_at.isoformat()}
        )

    def test_serializer_fields_decided(self):
        # Each field of the model is returned by the API, or left out here on purpose. A new field fails this
        # test until someone decides if a role with viewOIDCAPITokenIssuer may read it.
        left_out = set()
        self.assertEqual(
            {field.name for field in OIDCAPITokenIssuer._meta.concrete_fields},
            set(OIDCAPITokenIssuerSerializer.Meta.fields) | left_out,
        )
