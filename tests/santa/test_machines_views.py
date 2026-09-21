import datetime

from django.contrib.auth.models import Group
from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string

from accounts.models import Policy, User
from tests.zentral_test_utils.login_case import LoginCase
from zentral.contrib.inventory.models import Tag
from zentral.contrib.santa.models import Configuration, EnrolledMachine, ScopedClientMode
from zentral.utils.time import naive_utcnow

from .utils import force_configuration, force_enrolled_machine


class SantaMachinesViewsTestCase(TestCase, LoginCase):
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

    @staticmethod
    def at(day):
        return datetime.datetime(2026, 9, day, tzinfo=datetime.UTC)

    def set_policy_for_actions(self, *actions):
        serialized = ", ".join(f'Santa::Action::"{action}"' for action in actions)
        Policy.objects.update_or_create(
            name="Santa tests",
            defaults={"source": ("permit ("
                                 f' principal in Role::"{self.group.pk}",'
                                 f" action in [{serialized}],"
                                 "  resource"
                                 ");\n")},
        )

    def login_with_view_enrolled_machine(self, *extra_actions):
        # the page links the configuration and the entries, which santa.view_configuration opens
        self.login("santa.view_configuration")
        self.set_policy_for_actions("viewEnrolledMachine", *extra_actions)

    def machine_url(self, enrolled_machine):
        return reverse("santa:machine", args=(enrolled_machine.get_urlsafe_serial_number(),))

    def filtered_machine_urls(self, **params):
        """The machines a filter selects, as URLs: one result redirects to its page."""
        response = self.client.get(reverse("santa:machines"), params)
        if response.status_code == 302:
            return {response.url}
        return {self.machine_url(em) for em in response.context["object_list"]}

    def force_client_mode(self, configuration, lockdown=True, name=None, tags=None,
                          excluded_tags=None, **kwargs):
        entry = ScopedClientMode.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            client_mode=Configuration.LOCKDOWN_MODE if lockdown else Configuration.MONITOR_MODE,
            **kwargs,
        )
        entry.tags.set(tags or [])
        entry.excluded_tags.set(excluded_tags or [])
        return entry

    # machine list

    def test_machines_redirect(self):
        self.login_redirect("machines")

    def test_machines_permission_denied(self):
        self.login()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual(response.status_code, 403)

    def test_machines(self):
        enrolled_machine = force_enrolled_machine(last_preflight_at=self.at(1))
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/machine_list.html")
        self.assertContains(response, enrolled_machine.serial_number)
        self.assertContains(response, self.machine_url(enrolled_machine))

    def test_machines_one_row_per_serial_number(self):
        serial_number = get_random_string(12)
        current = force_enrolled_machine(serial_number=serial_number, santa_version="2026.7",
                                         last_preflight_at=self.at(2))
        force_enrolled_machine(serial_number=serial_number, santa_version="2024.5",
                               last_preflight_at=self.at(1))
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual([em.pk for em in response.context["object_list"]], [current.pk])
        self.assertContains(response, "2026.7")
        self.assertNotContains(response, "2024.5")

    def test_machines_filter_skips_a_stale_row(self):
        serial_number = get_random_string(12)
        force_enrolled_machine(serial_number=serial_number, santa_version="2026.7",
                               last_preflight_at=self.at(2))
        force_enrolled_machine(serial_number=serial_number, santa_version="2024.5",
                               last_preflight_at=self.at(1))
        other = force_enrolled_machine(santa_version="2024.5", last_preflight_at=self.at(1))
        self.login_with_view_enrolled_machine()
        # the machine reports 2026.7. Its stale row reports 2024.5, and does not put it in the page
        self.assertEqual(self.filtered_machine_urls(santa_version="2024.5"), {self.machine_url(other)})

    def test_machines_version_choices_exclude_a_stale_row(self):
        serial_number = get_random_string(12)
        force_enrolled_machine(serial_number=serial_number, santa_version="2026.7",
                               last_preflight_at=self.at(2))
        force_enrolled_machine(serial_number=serial_number, santa_version="2024.5",
                               last_preflight_at=self.at(1))
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual(
            [v for v, _ in response.context["form"].fields["santa_version"].choices],
            ["", "2026.7"],
        )

    def test_machines_search(self):
        enrolled_machine = force_enrolled_machine(primary_user="alice@zentral.com")
        force_enrolled_machine(primary_user="bob@zentral.com")
        self.login_with_view_enrolled_machine()
        self.assertEqual(self.filtered_machine_urls(q="alice"), {self.machine_url(enrolled_machine)})

    def test_machines_filter_configuration(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        force_enrolled_machine()
        self.login_with_view_enrolled_machine()
        self.assertEqual(self.filtered_machine_urls(configuration=configuration.pk),
                         {self.machine_url(enrolled_machine)})

    def test_machines_filter_client_mode(self):
        enrolled_machine = force_enrolled_machine(lockdown=True)
        force_enrolled_machine(lockdown=False)
        self.login_with_view_enrolled_machine()
        self.assertEqual(self.filtered_machine_urls(client_mode=Configuration.LOCKDOWN_MODE),
                         {self.machine_url(enrolled_machine)})

    def test_machines_filter_sync_state(self):
        ok = force_enrolled_machine(last_sync_ok=True)
        mismatch = force_enrolled_machine(last_sync_ok=False)
        never = force_enrolled_machine(last_sync_ok=None)
        queued = force_enrolled_machine(last_sync_ok=True,
                                        forced_sync_type=EnrolledMachine.SyncType.CLEAN)
        self.login_with_view_enrolled_machine()
        for value, expected in (("ok", {ok, queued}),
                                ("mismatch", {mismatch}),
                                ("unknown", {never}),
                                ("queued", {queued})):
            with self.subTest(value):
                self.assertEqual(self.filtered_machine_urls(sync_state=value),
                                 {self.machine_url(em) for em in expected})

    def test_machines_filter_last_sync_buckets(self):
        now = naive_utcnow()
        machines = {
            days: force_enrolled_machine(last_postflight_at=now - datetime.timedelta(days=days, hours=1))
            for days in (0, 6, 13, 29, 44, 89, 120)
        }
        never = force_enrolled_machine(last_postflight_at=None)
        self.login_with_view_enrolled_machine()
        # a bucket holds the machines of the younger ones too, on the boundaries of the metrics
        for value, expected_days in (("1", [0]),
                                     ("7", [0, 6]),
                                     ("14", [0, 6, 13]),
                                     ("30", [0, 6, 13, 29]),
                                     ("45", [0, 6, 13, 29, 44]),
                                     ("90", [0, 6, 13, 29, 44, 89]),
                                     ("older", [120])):
            with self.subTest(value):
                self.assertEqual(self.filtered_machine_urls(last_sync=value),
                                 {self.machine_url(machines[days]) for days in expected_days})
        self.assertEqual(self.filtered_machine_urls(last_sync="never"), {self.machine_url(never)})

    def test_machines_search_with_one_result_redirects(self):
        enrolled_machine = force_enrolled_machine(primary_user="alice@zentral.com")
        force_enrolled_machine(primary_user="bob@zentral.com")
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"), {"q": "alice"})
        self.assertRedirects(response, self.machine_url(enrolled_machine))

    def test_machines_search_with_two_results_does_not_redirect(self):
        force_enrolled_machine(primary_user="alice@zentral.com")
        force_enrolled_machine(primary_user="alice@acme.com")
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"), {"q": "alice"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["object_list"]), 2)

    def test_machines_one_machine_without_a_search_does_not_redirect(self):
        # a fleet with one machine would never get a list otherwise
        force_enrolled_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context["object_list"]), 1)

    def test_machines_pagination(self):
        for _ in range(3):
            force_enrolled_machine()
        self.login_with_view_enrolled_machine()
        self.user.items_per_page = 2
        self.user.save()
        response = self.client.get(reverse("santa:machines"))
        self.assertEqual(len(response.context["object_list"]), 2)
        self.assertEqual(response.context["page_obj"].paginator.num_pages, 2)
        response = self.client.get(reverse("santa:machines"), {"page": 2})
        self.assertEqual(len(response.context["object_list"]), 1)

    # machine page

    def test_machine_redirect(self):
        self.login_redirect("machine", "0123456789")

    def test_machine_permission_denied(self):
        enrolled_machine = force_enrolled_machine()
        self.login()
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.status_code, 403)

    def test_machine_not_enrolled(self):
        self.login_with_view_enrolled_machine()
        response = self.client.get(reverse("santa:machine", args=(get_random_string(12),)))
        self.assertEqual(response.status_code, 404)

    def test_machine(self):
        enrolled_machine = force_enrolled_machine(santa_version="2026.7", primary_user="alice",
                                                  last_preflight_at=self.at(1))
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "santa/machine_overview.html")
        self.assertContains(response, enrolled_machine.serial_number)
        self.assertContains(response, "2026.7")
        self.assertContains(response, "alice")

    def test_machine_enrollments(self):
        serial_number = get_random_string(12)
        current = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(2))
        stale = force_enrolled_machine(serial_number=serial_number, last_preflight_at=self.at(1))
        stale.save()
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(current))
        self.assertEqual([em.pk for em in response.context["enrolled_machines"]], [current.pk, stale.pk])
        self.assertEqual(response.context["enrolled_machine"], current)
        self.assertContains(response, str(stale.hardware_uuid))

    def test_machine_client_mode_from_the_configuration(self):
        enrolled_machine = force_enrolled_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["configured_client_mode"], "Monitor")
        self.assertEqual(response.context["client_mode_source"],
                         ("Configuration", reverse("santa:configuration",
                                                   args=(enrolled_machine.enrollment.configuration.pk,))))

    def test_machine_client_mode_from_an_entry(self):
        vip = Tag.objects.create(name=get_random_string(12))
        contractors = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[vip])
        # both entries are in scope, the Lockdown one at the tag level and the Monitor one as
        # everyone, so the narrower one decides
        winner = self.force_client_mode(configuration, lockdown=True, tags=[vip],
                                        excluded_tags=[contractors])
        self.force_client_mode(configuration, lockdown=False)
        # the entry of another configuration is not a candidate
        self.force_client_mode(force_configuration(), lockdown=True)
        self.login_with_view_enrolled_machine("viewScopedClientMode")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["configured_client_mode"], "Lockdown")
        self.assertEqual(response.context["client_mode_source"],
                         ("Scoped client mode", winner.get_absolute_url()))

    def test_machine_client_mode_entry_out(self):
        vip = Tag.objects.create(name=get_random_string(12))
        contractors = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[contractors])
        # a scope field that does not match, and an exclusion that does: the configuration decides
        self.force_client_mode(configuration, lockdown=True, tags=[vip])
        self.force_client_mode(configuration, lockdown=False, tags=[vip], excluded_tags=[contractors])
        self.login_with_view_enrolled_machine("viewScopedClientMode")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["configured_client_mode"], "Monitor")
        self.assertEqual(response.context["client_mode_source"],
                         ("Configuration", reverse("santa:configuration", args=(configuration.pk,))))

    def test_machine_source_not_linked_without_view_configuration(self):
        enrolled_machine = force_enrolled_machine()
        self.client.force_login(self.user)
        self.set_policy_for_actions("viewEnrolledMachine")
        response = self.client.get(self.machine_url(enrolled_machine))
        # the mode comes from the configuration, which the user may not open
        self.assertEqual(response.context["client_mode_source"], ("Configuration", None))
        self.assertEqual(response.context["event_detail_source_link"], ("Configuration", None))

    # the block notification button Zentral sends with the mode

    def test_machine_block_notification_button_from_the_configuration(self):
        configuration = force_configuration(event_detail_source=Configuration.EventDetailSource.CUSTOM,
                                            event_detail_url="https://www.example.com/%serial%",
                                            event_detail_text="Why?")
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["event_detail_source"], "Custom")
        self.assertEqual(response.context["event_detail_source_link"],
                         ("Configuration", reverse("santa:configuration", args=(configuration.pk,))))

    def test_machine_block_notification_button_from_the_entry(self):
        vip = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[vip])
        entry = self.force_client_mode(configuration, lockdown=True, tags=[vip],
                                       event_detail_source=ScopedClientMode.EventDetailSource.NONE)
        self.login_with_view_enrolled_machine("viewScopedClientMode")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["event_detail_source"], "None")
        self.assertEqual(response.context["event_detail_source_link"],
                         ("Scoped client mode", entry.get_absolute_url()))

    def test_machine_block_notification_button_inherited_by_the_entry(self):
        vip = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration(event_detail_source=Configuration.EventDetailSource.LOCAL)
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[vip])
        # the entry decides the mode, and leaves the button to the configuration
        self.force_client_mode(configuration, lockdown=True, tags=[vip],
                               event_detail_source=ScopedClientMode.EventDetailSource.INHERIT)
        self.login_with_view_enrolled_machine("viewScopedClientMode")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["configured_client_mode"], "Lockdown")
        self.assertEqual(response.context["event_detail_source"], "Local configuration")
        self.assertEqual(response.context["event_detail_source_link"],
                         ("Configuration", reverse("santa:configuration", args=(configuration.pk,))))

    def test_machine_client_mode_lockdown_wins_at_the_same_level(self):
        vip = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[vip])
        winner = self.force_client_mode(configuration, lockdown=True, tags=[vip])
        self.force_client_mode(configuration, lockdown=False, tags=[vip])
        self.login_with_view_enrolled_machine("viewScopedClientMode")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["configured_client_mode"], "Lockdown")
        self.assertEqual(response.context["client_mode_source"],
                         ("Scoped client mode", winner.get_absolute_url()))

    def test_machine_client_mode_entry_not_linked_without_permission(self):
        vip = Tag.objects.create(name=get_random_string(12))
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[vip])
        entry = self.force_client_mode(configuration, lockdown=True, tags=[vip])
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(enrolled_machine))
        # the mode is the one the machine gets, and the entry is named without a link to it
        self.assertEqual(response.context["configured_client_mode"], "Lockdown")
        self.assertEqual(response.context["client_mode_source"], ("Scoped client mode", None))
        self.assertNotContains(response, entry.name)

    def test_machine_clean_sync_actions(self):
        enrolled_machine = force_enrolled_machine()
        self.login_with_view_enrolled_machine("forceCleanSync")
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(
            [title for _, _, title, _ in response.context["actions"]],
            ["Force clean sync", "Force clean all sync", "Cancel queued clean sync"],
        )
        self.assertContains(
            response,
            reverse("santa:force_machine_clean_sync",
                    args=(enrolled_machine.get_urlsafe_serial_number(), "CLEAN")),
        )

    def test_machine_no_clean_sync_action_without_permission(self):
        enrolled_machine = force_enrolled_machine()
        self.login_with_view_enrolled_machine()
        response = self.client.get(self.machine_url(enrolled_machine))
        self.assertEqual(response.context["actions"], [])

    # the links to the machine list

    def test_index_machine_count_link(self):
        configuration = force_configuration()
        force_enrolled_machine(configuration=configuration)
        self.login("santa.view_configuration")
        link = f'{reverse("santa:machines")}?configuration={configuration.pk}'
        response = self.client.get(reverse("santa:index"))
        self.assertNotContains(response, link)
        self.set_policy_for_actions("viewEnrolledMachine")
        response = self.client.get(reverse("santa:index"))
        self.assertContains(response, link)

    def test_index_machine_count_counts_machines(self):
        configuration = force_configuration()
        serial_number = get_random_string(12)
        # two enrollments of one machine: two rows, and the count links to a list of machines
        force_enrolled_machine(configuration=configuration, serial_number=serial_number,
                               last_preflight_at=self.at(2))
        force_enrolled_machine(configuration=configuration, serial_number=serial_number,
                               last_preflight_at=self.at(1))
        self.login("santa.view_configuration")
        response = self.client.get(reverse("santa:index"))
        self.assertEqual(response.context["configurations"][0]["machine_count"], 1)

    def test_configuration_machines_link(self):
        configuration = force_configuration()
        self.login("santa.view_configuration")
        machines_link = f'{reverse("santa:machines")}?configuration={configuration.pk}'
        response = self.client.get(reverse("santa:configuration", args=(configuration.pk,)))
        self.assertNotContains(response, machines_link)
        self.set_policy_for_actions("viewEnrolledMachine")
        response = self.client.get(reverse("santa:configuration", args=(configuration.pk,)))
        self.assertContains(response, machines_link)
