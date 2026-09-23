from accounts.models import User
from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string
from pbac.engine import engine
from pbac.entities import Entity
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.santa.models import Configuration, ScopedClientMode
from zentral.contrib.santa.pbac import get_scoped_client_mode_resource
from .utils import force_configuration


class SantaScopedClientModePBACTestCase(TestCase, LoginCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("mothra", "mothra@zentral.io", get_random_string(12))
        cls.group = Group.objects.create(name=get_random_string(12))
        cls.user.groups.set([cls.group])

    def _get_group(self):
        return self.group

    def _get_user(self):
        return self.user

    def _get_url_namespace(self):
        return "santa"

    def force_scoped_client_mode(self, configuration):
        return ScopedClientMode.objects.create(
            configuration=configuration,
            name=get_random_string(12),
            client_mode=Configuration.MONITOR_MODE,
        )

    def policy(self, *statements):
        # set_policy keeps one policy, so the legacy configuration permissions go in here too
        role = str(Entity("Role", str(self._get_group().pk)))
        legacy = [engine.legacy_perm_actions["santa.view_configuration"],
                  engine.module_legacy_perm_actions["santa"]]
        source = (
            'permit (\n'
            f'  principal in {role},\n'
            f'  action in [{", ".join(str(a) for a in legacy)}],\n'
            '  resource\n'
            ');\n'
        )
        for statement in statements:
            source += statement.replace("ROLE", role) + "\n"
        return source

    def assert_breadcrumbs(self, response, configuration):
        self.assertContains(response, f'<a href="{configuration.get_absolute_url()}">{configuration.name}</a>')
        self.assertContains(response, f'<a href="{self.tab_url(configuration)}">Scoped client modes</a>')

    def tab_url(self, configuration):
        return reverse("santa:configuration_scoped_client_modes", args=(configuration.pk,))

    # resource

    def test_resource(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        resource = get_scoped_client_mode_resource(scm)
        self.assertEqual(str(resource), f'Santa::ScopedClientMode::"{scm.pk}"')
        self.assertEqual(resource.attrs, {})
        self.assertEqual([str(p) for p in resource.parents],
                         [f'Santa::Configuration::"{configuration.pk}"'])
        self.assertEqual(resource.parents[0].attrs, {"name": configuration.name})

    # create

    def test_tab_hides_the_create_button_without_a_policy(self):
        configuration = force_configuration()
        self.login_with_policy(self.policy())
        response = self.client.get(self.tab_url(configuration))
        self.assertNotContains(response, reverse("santa:create_scoped_client_mode", args=(configuration.pk,)))

    def test_tab_shows_the_create_button(self):
        configuration = force_configuration()
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action == Santa::Action::"createScopedClientMode",'
            f' resource == Santa::Configuration::"{configuration.pk}");'
        ))
        response = self.client.get(self.tab_url(configuration))
        self.assertContains(response, reverse("santa:create_scoped_client_mode", args=(configuration.pk,)))

    def test_create_denied_without_a_policy(self):
        configuration = force_configuration()
        self.login_with_policy(self.policy())
        response = self.client.post(
            reverse("santa:create_scoped_client_mode", args=(configuration.pk,)),
            {"name": get_random_string(12),
             "client_mode": Configuration.LOCKDOWN_MODE,
             "event_detail_source": ScopedClientMode.EventDetailSource.INHERIT},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ScopedClientMode.objects.count(), 0)

    def test_create(self):
        configuration = force_configuration()
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action == Santa::Action::"createScopedClientMode",'
            f' resource == Santa::Configuration::"{configuration.pk}");'
        ))
        url = reverse("santa:create_scoped_client_mode", args=(configuration.pk,))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assert_breadcrumbs(response, configuration)
        self.assertContains(response, f'class="btn btn-outline-secondary" href="{self.tab_url(configuration)}"')
        name = get_random_string(12)
        response = self.client.post(
            url,
            {"name": name,
             "client_mode": Configuration.LOCKDOWN_MODE,
             "event_detail_source": ScopedClientMode.EventDetailSource.INHERIT},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        entry = ScopedClientMode.objects.get(name=name)
        self.assertEqual(response.redirect_chain, [(entry.get_absolute_url(), 302)])

    def test_create_denied_on_another_configuration(self):
        configuration = force_configuration()
        other = force_configuration()
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action == Santa::Action::"createScopedClientMode",'
            f' resource == Santa::Configuration::"{other.pk}");'
        ))
        response = self.client.get(reverse("santa:create_scoped_client_mode", args=(configuration.pk,)))
        self.assertEqual(response.status_code, 403)

    # update

    def update_policy(self, configuration):
        return self.policy(
            f'permit (principal in ROLE, action == Santa::Action::"updateScopedClientMode",'
            f' resource in Santa::Configuration::"{configuration.pk}");',
        )

    def test_update_denied_without_a_policy(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy())
        response = self.client.get(
            reverse("santa:update_scoped_client_mode", args=(configuration.pk, scm.pk))
        )
        self.assertEqual(response.status_code, 403)

    def test_update(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.update_policy(configuration))
        url = reverse("santa:update_scoped_client_mode", args=(configuration.pk, scm.pk))
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assert_breadcrumbs(response, configuration)
        response = self.client.post(
            url,
            {"name": scm.name,
             "client_mode": Configuration.LOCKDOWN_MODE,
             "event_detail_source": ScopedClientMode.EventDetailSource.INHERIT},
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        scm.refresh_from_db()
        self.assertEqual(scm.client_mode, Configuration.LOCKDOWN_MODE)

    def assert_the_entry_carries_its_configuration(self, url):
        with CaptureQueriesContext(connection) as ctx:
            response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertEqual([q["sql"] for q in ctx.captured_queries
                          if 'FROM "santa_configuration"' in q["sql"]], [])

    def test_the_entry_carries_its_configuration(self):
        # the PBAC parent entity, the audit event and the success URL all read it
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action in [Santa::Action::"updateScopedClientMode",'
            f' Santa::Action::"deleteScopedClientMode"],'
            f' resource in Santa::Configuration::"{configuration.pk}");'
        ))
        self.assert_the_entry_carries_its_configuration(
            reverse("santa:update_scoped_client_mode", args=(configuration.pk, scm.pk))
        )
        self.assert_the_entry_carries_its_configuration(
            reverse("santa:delete_scoped_client_mode", args=(configuration.pk, scm.pk))
        )

    def test_update_denied_on_another_configuration(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(force_configuration())
        self.login_with_policy(self.update_policy(configuration))
        response = self.client.get(
            reverse("santa:update_scoped_client_mode", args=(scm.configuration.pk, scm.pk))
        )
        self.assertEqual(response.status_code, 403)

    # view

    def test_tab_hides_the_entries_without_a_policy(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy())
        response = self.client.get(self.tab_url(configuration))
        self.assertNotContains(response, scm.name)

    def test_tab_shows_the_entries(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action == Santa::Action::"viewScopedClientMode",'
            f' resource in Santa::Configuration::"{configuration.pk}");'
        ))
        response = self.client.get(self.tab_url(configuration))
        self.assertContains(response, scm.name)
        self.assertNotContains(
            response, reverse("santa:delete_scoped_client_mode", args=(configuration.pk, scm.pk))
        )

    # delete

    def test_delete_denied_without_a_policy(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy())
        response = self.client.get(
            reverse("santa:delete_scoped_client_mode", args=(configuration.pk, scm.pk))
        )
        self.assertEqual(response.status_code, 403)

    def test_delete(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.login_with_policy(self.policy(
            f'permit (principal in ROLE, action in [Santa::Action::"viewScopedClientMode",'
            f' Santa::Action::"deleteScopedClientMode"],'
            f' resource in Santa::Configuration::"{configuration.pk}");'
        ))
        url = reverse("santa:delete_scoped_client_mode", args=(configuration.pk, scm.pk))
        response = self.client.get(self.tab_url(configuration))
        self.assertContains(response, url)
        self.assert_breadcrumbs(self.client.get(url), configuration)
        response = self.client.post(url, follow=True)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.redirect_chain, [(self.tab_url(configuration), 302)])
        self.assertEqual(ScopedClientMode.objects.filter(pk=scm.pk).count(), 0)
