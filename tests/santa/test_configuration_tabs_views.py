from django.contrib.auth.models import Group
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import Configuration, Enrollment, ScopedClientMode, ScopedPathRegex

from .utils import force_configuration, force_realm_user, force_rule, force_voting_group


class SantaConfigurationTabsViewsTestCase(TestCase, LoginCase):
    """The tabs of a configuration page."""

    maxDiff = None

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
        return "santa"

    # utils

    def login_with_actions(self, *legacy_perms, actions=()):
        self.login(*legacy_perms)
        serialized = ", ".join(f'Santa::Action::"{action}"' for action in actions)
        Policy.objects.update_or_create(
            name="Santa tests",
            defaults={"source": ("permit ("
                                 f' principal in Role::"{self.group.pk}",'
                                 f" action in [{serialized}],"
                                 "  resource"
                                 ");\n")},
        )

    def set_items_per_page(self, items_per_page):
        self.user.items_per_page = items_per_page
        self.user.save()

    def url(self, url_name, configuration):
        return reverse(f"santa:{url_name}", args=(configuration.pk,))

    def force_scoped_client_mode(self, configuration, name=None, client_mode=Configuration.MONITOR_MODE, tags=None):
        scm = ScopedClientMode.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            client_mode=client_mode,
        )
        if tags:
            scm.tags.set(tags)
        return scm

    def force_scoped_path_regex(self, configuration, name=None, regex=None,
                                policy=ScopedPathRegex.Policy.BLOCK, tags=None):
        spr = ScopedPathRegex.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            policy=policy,
            regex=regex or f"/{get_random_string(12)}/",
        )
        if tags:
            spr.tags.set(tags)
        return spr

    def item_rows(self, response):
        return [row["item"] for row in response.context["rows"]]

    SCOPED_TABS = ("configuration_scoped_client_modes", "configuration_scoped_path_regexes")

    # the tab bar

    def tab_titles(self, response):
        return [title for _, title, _ in response.context["tabs"]]

    def test_the_tabs(self):
        configuration = force_configuration()
        force_rule(configuration=configuration)
        self.force_scoped_client_mode(configuration)
        for _ in range(2):
            self.force_scoped_path_regex(configuration)
        self.login_with_actions("santa.view_configuration", "santa.view_rule",
                                actions=("viewScopedClientMode", "viewScopedPathRegex"))
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(
            response.context["tabs"],
            [("overview", "Overview", self.url("configuration", configuration)),
             ("rules", "Rule (1)", self.url("configuration_rules", configuration)),
             ("scoped_client_modes", "Scoped client mode (1)",
              self.url("configuration_scoped_client_modes", configuration)),
             ("scoped_path_regexes", "Scoped path regexes (2)",
              self.url("configuration_scoped_path_regexes", configuration))],
        )

    def test_a_tab_counts_the_entries_the_user_can_view(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration)
        self.force_scoped_path_regex(configuration)
        self.force_scoped_path_regex(force_configuration())
        self.login_with_actions("santa.view_configuration", actions=("viewScopedPathRegex",))
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual(self.tab_titles(response),
                         ["Overview", "Scoped client modes (0)", "Scoped path regex (1)"])

    def test_the_count_of_a_tab_follows_its_search(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration)
        self.force_scoped_client_mode(configuration, client_mode=Configuration.LOCKDOWN_MODE)
        self.force_scoped_path_regex(configuration)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedClientMode", "viewScopedPathRegex"))
        response = self.client.get(self.url("configuration_scoped_client_modes", configuration),
                                   {"client_mode": Configuration.LOCKDOWN_MODE})
        self.assertEqual(self.tab_titles(response),
                         ["Overview", "Scoped client mode (1)", "Scoped path regex (1)"])
        # the other tabs have no search
        response = self.client.get(self.url("configuration_scoped_path_regexes", configuration))
        self.assertEqual(self.tab_titles(response),
                         ["Overview", "Scoped client modes (2)", "Scoped path regex (1)"])

    def test_each_tab_is_active_on_its_own_page(self):
        configuration = force_configuration()
        self.login("santa.view_configuration", "santa.view_rule")
        for name, _, url in self.client.get(configuration.get_absolute_url()).context["tabs"]:
            with self.subTest(tab=name):
                response = self.client.get(url)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.context["tab"], name)
                self.assertContains(response, f'class="nav-link active" href="{url}"', count=1)

    def test_the_rules_tab_needs_view_rule(self):
        configuration = force_configuration()
        self.login("santa.view_configuration")
        response = self.client.get(configuration.get_absolute_url())
        self.assertEqual([name for name, _, _ in response.context["tabs"]],
                         ["overview", "scoped_client_modes", "scoped_path_regexes"])
        self.assertNotContains(response, self.url("configuration_rules", configuration))

    def test_the_rules_tab_without_view_configuration(self):
        configuration = force_configuration()
        self.login("santa.view_rule")
        response = self.client.get(self.url("configuration_rules", configuration))
        self.assertEqual(response.status_code, 200)
        # only the tabs the user can open
        self.assertEqual([name for name, _, _ in response.context["tabs"]], ["rules"])

    # the overview

    def test_the_overview_gives_the_voting_groups_then_the_enrollments(self):
        configuration = force_configuration()
        _, realm_user = force_realm_user()
        force_voting_group(configuration, realm_user)
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(12))
        Enrollment.objects.create(configuration=configuration,
                                  secret=EnrollmentSecret.objects.create(meta_business_unit=mbu))
        self.login("santa.view_configuration", "santa.view_votinggroup", "santa.view_enrollment")
        response = self.client.get(configuration.get_absolute_url())
        content = response.content.decode("utf-8")
        # the last row of the attributes, then the two sections
        self.assertLess(content.index("Sync incident severity"), content.index("Voting group (1)"))
        self.assertLess(content.index("Voting group (1)"), content.index("Enrollment (1)"))

    def test_the_overview_has_no_entry_and_no_rule(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        spr = self.force_scoped_path_regex(configuration)
        rule = force_rule(configuration=configuration)
        self.login_with_actions("santa.view_configuration", "santa.view_rule",
                                actions=("viewScopedClientMode", "viewScopedPathRegex"))
        response = self.client.get(configuration.get_absolute_url())
        for value in (scm.name, spr.name, spr.regex, rule.target.identifier):
            self.assertNotContains(response, value)

    # the two tabs of the scoped entries

    def test_scoped_tabs_redirect(self):
        configuration = force_configuration()
        for url_name in self.SCOPED_TABS:
            with self.subTest(url_name=url_name):
                self.login_redirect(url_name, configuration.pk)

    def test_scoped_tabs_permission_denied(self):
        configuration = force_configuration()
        self.login("santa.view_rule")
        for url_name in self.SCOPED_TABS:
            with self.subTest(url_name=url_name):
                response = self.client.get(self.url(url_name, configuration))
                self.assertEqual(response.status_code, 403)

    def test_scoped_tabs_unknown_configuration(self):
        self.login("santa.view_configuration")
        for url_name in self.SCOPED_TABS:
            with self.subTest(url_name=url_name):
                response = self.client.get(reverse(f"santa:{url_name}", args=(0,)))
                self.assertEqual(response.status_code, 404)

    # the scoped client modes tab

    def test_scoped_client_modes_pagination(self):
        configuration = force_configuration()
        first = self.force_scoped_client_mode(configuration, name="a" + get_random_string(12))
        second = self.force_scoped_client_mode(configuration, name="b" + get_random_string(12),
                                               client_mode=Configuration.LOCKDOWN_MODE)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedClientMode",))
        self.set_items_per_page(1)
        url = self.url("configuration_scoped_client_modes", configuration)
        response = self.client.get(url)
        self.assertTemplateUsed(response, "santa/configuration_scoped_client_modes.html")
        self.assertContains(response, "Scoped client modes (2)")
        self.assertEqual(self.item_rows(response), [first])
        self.assertEqual(response.context["next_url"], "?page=2")
        response = self.client.get(url, {"page": 2})
        self.assertEqual(self.item_rows(response), [second])
        self.assertEqual(response.context["previous_url"], "?page=1")

    def test_scoped_client_modes_search_on_the_mode(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration)
        lockdown = self.force_scoped_client_mode(configuration, client_mode=Configuration.LOCKDOWN_MODE)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedClientMode",))
        response = self.client.get(self.url("configuration_scoped_client_modes", configuration),
                                   {"client_mode": Configuration.LOCKDOWN_MODE})
        self.assertContains(response, "Scoped client mode (1)")
        self.assertEqual(self.item_rows(response), [lockdown])

    def test_scoped_client_modes_no_result(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedClientMode",))
        url = self.url("configuration_scoped_client_modes", configuration)
        response = self.client.get(url, {"client_mode": Configuration.LOCKDOWN_MODE})
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, f'{url}">all the items')

    def test_the_link_to_a_scoped_client_mode_finds_it(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration, name="a" + get_random_string(12))
        entry = self.force_scoped_client_mode(configuration, name="b" + get_random_string(12),
                                              client_mode=Configuration.LOCKDOWN_MODE)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedClientMode",))
        # without the search, the entry is on the second page
        self.set_items_per_page(1)
        response = self.client.get(entry.get_absolute_url())
        self.assertEqual(self.item_rows(response), [entry])

    def test_scoped_client_modes_buttons_of_the_page(self):
        configuration = force_configuration()
        first = self.force_scoped_client_mode(configuration, name="a" + get_random_string(12))
        second = self.force_scoped_client_mode(configuration, name="b" + get_random_string(12),
                                               client_mode=Configuration.LOCKDOWN_MODE)
        self.login_with_actions("santa.view_configuration",
                                actions=("viewScopedClientMode", "updateScopedClientMode", "deleteScopedClientMode"))
        self.set_items_per_page(1)
        response = self.client.get(self.url("configuration_scoped_client_modes", configuration), {"page": 2})
        self.assertEqual(response.context["rows"], [{"item": second, "can_update": True, "can_delete": True}])
        self.assertContains(response, reverse("santa:update_scoped_client_mode", args=(configuration.pk, second.pk)))
        self.assertNotContains(response, reverse("santa:update_scoped_client_mode", args=(configuration.pk, first.pk)))

    def test_scoped_client_modes_queries_do_not_grow_with_the_entries(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_client_mode(configuration, tags=[tag])
        self.login_with_actions("santa.view_configuration",
                                actions=("viewScopedClientMode", "updateScopedClientMode", "deleteScopedClientMode"))
        url = self.url("configuration_scoped_client_modes", configuration)
        with CaptureQueriesContext(connection) as one_entry:
            self.assertEqual(self.client.get(url).status_code, 200)
        self.force_scoped_client_mode(configuration, client_mode=Configuration.LOCKDOWN_MODE, tags=[tag])
        with CaptureQueriesContext(connection) as two_entries:
            self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(len(one_entry.captured_queries), len(two_entries.captured_queries))

    # the scoped path regexes tab

    def test_scoped_path_regexes_pagination(self):
        configuration = force_configuration()
        entries = [self.force_scoped_path_regex(configuration, name=f"{i}{get_random_string(12)}")
                   for i in range(3)]
        self.login_with_actions("santa.view_configuration", actions=("viewScopedPathRegex",))
        self.set_items_per_page(2)
        url = self.url("configuration_scoped_path_regexes", configuration)
        response = self.client.get(url)
        self.assertTemplateUsed(response, "santa/configuration_scoped_path_regexes.html")
        self.assertContains(response, "Scoped path regexes (3)")
        self.assertEqual(self.item_rows(response), entries[:2])
        self.assertEqual(response.context["next_url"], "?page=2")
        response = self.client.get(url, {"page": 2})
        self.assertEqual(self.item_rows(response), entries[2:])
        self.assertEqual(response.context["previous_url"], "?page=1")

    def test_scoped_path_regexes_search(self):
        configuration = force_configuration()
        homebrew = self.force_scoped_path_regex(configuration, name="Developer tools", regex="/opt/homebrew/",
                                                policy=ScopedPathRegex.Policy.ALLOW)
        tmp = self.force_scoped_path_regex(configuration, name="Temporary files", regex="/tmp/",
                                           policy=ScopedPathRegex.Policy.BLOCK)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedPathRegex",))
        url = self.url("configuration_scoped_path_regexes", configuration)
        for query, expected in (({"q": "developer"}, [homebrew]),  # the name, in any case
                                ({"q": "homebrew"}, [homebrew]),  # the pattern
                                ({"policy": "BLOCK"}, [tmp]),
                                ({"policy": "ALLOW", "q": "tmp"}, [])):
            with self.subTest(query=query):
                response = self.client.get(url, query)
                self.assertEqual(self.item_rows(response), expected)

    def test_scoped_path_regexes_no_result(self):
        configuration = force_configuration()
        self.force_scoped_path_regex(configuration)
        self.login_with_actions("santa.view_configuration", actions=("viewScopedPathRegex",))
        url = self.url("configuration_scoped_path_regexes", configuration)
        response = self.client.get(url, {"q": "does not exist"})
        self.assertContains(response, "We didn't find any item related to your search")
        self.assertContains(response, f'{url}">all the items')

    def test_the_link_to_a_scoped_path_regex_finds_it(self):
        configuration = force_configuration()
        for i in range(2):
            self.force_scoped_path_regex(configuration, name=f"{i}{get_random_string(12)}")
        entry = self.force_scoped_path_regex(configuration, name=f"9{get_random_string(12)}")
        self.login_with_actions("santa.view_configuration", actions=("viewScopedPathRegex",))
        # without the search, the entry is on the third page
        self.set_items_per_page(1)
        response = self.client.get(entry.get_absolute_url())
        self.assertEqual(self.item_rows(response), [entry])

    def test_scoped_path_regexes_queries_do_not_grow_with_the_entries(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_path_regex(configuration, tags=[tag])
        self.login_with_actions("santa.view_configuration",
                                actions=("viewScopedPathRegex", "updateScopedPathRegex", "deleteScopedPathRegex"))
        url = self.url("configuration_scoped_path_regexes", configuration)
        with CaptureQueriesContext(connection) as one_entry:
            self.assertEqual(self.client.get(url).status_code, 200)
        for _ in range(4):
            self.force_scoped_path_regex(configuration, tags=[tag])
        with CaptureQueriesContext(connection) as five_entries:
            self.assertEqual(self.client.get(url).status_code, 200)
        self.assertEqual(len(one_entry.captured_queries), len(five_entries.captured_queries))
