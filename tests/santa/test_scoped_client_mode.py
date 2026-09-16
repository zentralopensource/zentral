import json
import uuid

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import Configuration, Enrollment, ScopedClientMode
from .utils import force_configuration, force_enrolled_machine, force_realm


class SantaScopedClientModeTestCase(TestCase):
    def force_scoped_client_mode(self, configuration, name=None, lockdown=False, **kwargs):
        tags = kwargs.pop("tags", None)
        excluded_tags = kwargs.pop("excluded_tags", None)
        scm = ScopedClientMode.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            client_mode=Configuration.LOCKDOWN_MODE if lockdown else Configuration.MONITOR_MODE,
            **kwargs,
        )
        if tags:
            scm.tags.set(tags)
        if excluded_tags:
            scm.excluded_tags.set(excluded_tags)
        return scm

    def enrolled_machine(self, configuration, serial_number="0123456789", primary_user=None, tags=None):
        return force_enrolled_machine(configuration=configuration, serial_number=serial_number,
                                      primary_user=primary_user, tags=tags, for_sync=True)

    def for_machine(self, configuration, serial_number="0123456789", primary_user=None, tag_ids=None):
        return list(ScopedClientMode.objects.for_machine(configuration, serial_number,
                                                         primary_user, tag_ids or []))

    # scope

    def test_no_scope_matches_every_machine(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.assertEqual(self.for_machine(configuration), [scm])

    def test_serial_numbers(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration, serial_numbers=["0123456789"])
        self.assertEqual(self.for_machine(configuration), [scm])
        self.assertEqual(self.for_machine(configuration, serial_number="9876543210"), [])

    def test_excluded_serial_numbers(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration, excluded_serial_numbers=["0123456789"])
        self.assertEqual(self.for_machine(configuration), [])

    def test_primary_users(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration, primary_users=["yolo"])
        self.assertEqual(self.for_machine(configuration, primary_user="yolo"), [scm])
        self.assertEqual(self.for_machine(configuration, primary_user="fomo"), [])

    def test_machine_without_primary_user_skips_every_user_scoped_entry(self):
        # inherited from the rule download: an excluded list is enough to disqualify the machine
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration, primary_users=["yolo"])
        self.force_scoped_client_mode(configuration, excluded_primary_users=["yolo"])
        self.assertEqual(self.for_machine(configuration), [])

    def test_tags(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        other_tag = Tag.objects.create(name=get_random_string(12))
        scm = self.force_scoped_client_mode(configuration, tags=[tag])
        self.assertEqual(self.for_machine(configuration, tag_ids=[tag.pk]), [scm])
        self.assertEqual(self.for_machine(configuration, tag_ids=[other_tag.pk]), [])

    def test_excluded_tags(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_client_mode(configuration, excluded_tags=[tag])
        self.assertEqual(self.for_machine(configuration, tag_ids=[tag.pk]), [])
        # unlike the primary users, an excluded list alone does not disqualify a machine with no tag
        self.assertEqual(len(self.for_machine(configuration)), 1)

    def test_other_configuration(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(force_configuration())
        self.assertEqual(self.for_machine(configuration), [])

    # precedence

    def test_precedence_rank(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        for kwargs, rank in (
            ({"serial_numbers": ["0123456789"]}, ScopedClientMode.RANK_SERIAL),
            ({"primary_users": ["yolo"]}, ScopedClientMode.RANK_USER),
            ({"tags": [tag]}, ScopedClientMode.RANK_TAG),
            ({}, ScopedClientMode.RANK_ALL),
        ):
            scm = self.force_scoped_client_mode(configuration, **kwargs)
            self.assertEqual(scm.precedence_rank(), rank)

    def test_narrower_reach_wins_over_lockdown(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_client_mode(configuration, lockdown=True, tags=[tag])
        serial_scoped = self.force_scoped_client_mode(configuration, serial_numbers=["0123456789"])
        winner = Configuration.resolve_scoped_client_mode(
            self.for_machine(configuration, tag_ids=[tag.pk])
        )
        self.assertEqual(winner, serial_scoped)

    def test_lockdown_wins_at_equal_reach(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(configuration, name="a")
        lockdown = self.force_scoped_client_mode(configuration, name="b", lockdown=True)
        self.assertEqual(Configuration.resolve_scoped_client_mode(self.for_machine(configuration)),
                         lockdown)

    def test_name_breaks_the_last_tie(self):
        configuration = force_configuration()
        first = self.force_scoped_client_mode(configuration, name="a")
        self.force_scoped_client_mode(configuration, name="b")
        self.assertEqual(Configuration.resolve_scoped_client_mode(self.for_machine(configuration)),
                         first)

    def test_no_entry(self):
        self.assertIsNone(Configuration.resolve_scoped_client_mode([]))

    # preflight

    def test_no_entry_keeps_the_configuration_mode(self):
        configuration = force_configuration(lockdown=True)
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_entry_overrides_the_configuration_mode(self):
        configuration = force_configuration(lockdown=True)
        self.force_scoped_client_mode(configuration)
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

    def test_entry_out_of_scope_keeps_the_configuration_mode(self):
        configuration = force_configuration(lockdown=True)
        self.force_scoped_client_mode(configuration, serial_numbers=["9876543210"])
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    # event detail

    def test_inherit_keeps_the_computed_voting_portal_url(self):
        configuration = force_configuration(
            voting_realm=force_realm(user_portal=True),
            event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL,
        )
        self.force_scoped_client_mode(configuration)
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertIn("/up/santa/event_detail/", config["event_detail_url"])
        self.assertEqual(config["event_detail_text"], Configuration.DEFAULT_EVENT_DETAIL_TEXT)

    def test_entry_custom_source_overrides(self):
        configuration = force_configuration(
            event_detail_source=Configuration.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/configuration/",
            event_detail_text="Configuration",
        )
        self.force_scoped_client_mode(
            configuration,
            event_detail_source=ScopedClientMode.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/entry/",
            event_detail_text="Entry",
        )
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["event_detail_url"], "https://www.example.com/entry/")
        self.assertEqual(config["event_detail_text"], "Entry")

    def test_entry_none_source_removes_the_button(self):
        configuration = force_configuration(
            event_detail_source=Configuration.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/configuration/",
        )
        self.force_scoped_client_mode(
            configuration, event_detail_source=ScopedClientMode.EventDetailSource.NONE
        )
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["event_detail_url"], Configuration.NO_EVENT_DETAIL_URL)
        self.assertNotIn("event_detail_text", config)

    def test_entry_voting_portal_source_uses_the_configuration_realm(self):
        configuration = force_configuration(voting_realm=force_realm(user_portal=True))
        self.force_scoped_client_mode(
            configuration, event_detail_source=ScopedClientMode.EventDetailSource.VOTING_PORTAL
        )
        config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertIn("/up/santa/event_detail/", config["event_detail_url"])

    def test_entry_voting_portal_source_without_a_realm_removes_the_button(self):
        configuration = force_configuration()
        self.force_scoped_client_mode(
            configuration, event_detail_source=ScopedClientMode.EventDetailSource.VOTING_PORTAL
        )
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR"):
            config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["event_detail_url"], Configuration.NO_EVENT_DETAIL_URL)

    def test_entry_source_does_not_resolve_the_configuration_button(self):
        # the voting portal URL of the configuration is a FK read and an error log when the
        # portal is off. The machines in scope do not get that button, so it is not resolved.
        configuration = force_configuration(
            event_detail_source=Configuration.EventDetailSource.VOTING_PORTAL,
        )
        self.force_scoped_client_mode(
            configuration,
            event_detail_source=ScopedClientMode.EventDetailSource.CUSTOM,
            event_detail_url="https://www.example.com/entry/",
        )
        with self.assertNoLogs("zentral.contrib.santa.models", level="ERROR"):
            config = configuration.get_sync_server_config(self.enrolled_machine(configuration), (2022, 1))
        self.assertEqual(config["event_detail_url"], "https://www.example.com/entry/")

    # queries

    def test_no_entry_costs_no_query(self):
        configuration = force_configuration()
        machine = self.enrolled_machine(configuration)
        with self.assertNumQueries(0):
            configuration.get_sync_server_config(machine, (2022, 1))

    def test_one_query_for_the_entries(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_client_mode(configuration, tags=[tag])
        machine = self.enrolled_machine(configuration, tags=[tag])
        # the entries, and the tag presence rides along in the same SELECT
        with self.assertNumQueries(1):
            configuration.get_sync_server_config(machine, (2022, 1))

    def test_without_the_annotations_the_method_asks(self):
        configuration = force_configuration()
        machine = force_enrolled_machine(configuration=configuration)
        with self.assertNumQueries(1):
            configuration.get_sync_server_config(machine, (2022, 1))

    def test_without_the_annotations_an_entry_costs_the_tags_too(self):
        # what an enrollment pays: the entries exist, and the tags are not annotated either
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_client_mode(configuration, tags=[tag])
        machine = force_enrolled_machine(configuration=configuration, tags=[tag])
        # the exists, the tags, then the entries
        with self.assertNumQueries(3):
            configuration.get_sync_server_config(machine, (2022, 1))

    # preflight view

    def force_enrollment(self, configuration, tags=None):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
        if tags:
            secret.tags.set(tags)
        return Enrollment.objects.create(configuration=configuration, secret=secret)

    def preflight(self, enrollment, hardware_uuid, serial_number, primary_user=None):
        data = {"os_build": "23G93",
                "santa_version": "2024.5",
                "hostname": "godzilla",
                "os_version": "14.6.1",
                "client_mode": "MONITOR",
                "serial_number": serial_number,
                "machine_id": str(hardware_uuid),
                "binary_rule_count": 0,
                "cdhash_rule_count": 0,
                "certificate_rule_count": 0,
                "compiler_rule_count": 0,
                "signingid_rule_count": 0,
                "teamid_rule_count": 0,
                "transitive_rule_count": 0}
        if primary_user:
            data["primary_user"] = primary_user
        response = self.client.post(
            reverse("santa_public:preflight", args=(hardware_uuid,)),
            json.dumps(data), content_type="application/json",
            headers={"Zentral-Authorization": f"Bearer {enrollment.secret.secret}"},
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def enrollment_preflight(self, enrollment, serial_number=None, primary_user=None):
        return self.preflight(enrollment, uuid.uuid4(), serial_number or get_random_string(12),
                              primary_user)

    def enrolled_machine_preflight(self, enrolled_machine, primary_user=None):
        return self.preflight(enrolled_machine.enrollment, enrolled_machine.hardware_uuid,
                              enrolled_machine.serial_number, primary_user)

    def test_preflight_applies_the_scoped_mode(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.force_scoped_client_mode(configuration, lockdown=True)
        response = self.enrolled_machine_preflight(enrolled_machine)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_preflight_applies_the_entry_scoped_on_a_tag(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[tag])
        self.force_scoped_client_mode(configuration, lockdown=True, tags=[tag])
        response = self.enrolled_machine_preflight(enrolled_machine)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_preflight_applies_the_entry_scoped_on_the_reported_primary_user(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.force_scoped_client_mode(configuration, lockdown=True, primary_users=["yolo@zentral.com"])
        response = self.enrolled_machine_preflight(enrolled_machine, primary_user="yolo@zentral.com")
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_preflight_ignores_an_entry_of_another_configuration(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.force_scoped_client_mode(force_configuration(), lockdown=True)
        response = self.enrolled_machine_preflight(enrolled_machine)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

    def test_enrollment_preflight_applies_the_scoped_mode(self):
        # the enrollment builds the machine without the annotations
        configuration = force_configuration()
        enrollment = self.force_enrollment(configuration)
        self.force_scoped_client_mode(configuration, lockdown=True)
        response = self.enrollment_preflight(enrollment)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_enrollment_preflight_applies_the_entry_scoped_on_an_enrollment_secret_tag(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        enrollment = self.force_enrollment(configuration, tags=[tag])
        self.force_scoped_client_mode(configuration, lockdown=True, tags=[tag])
        response = self.enrollment_preflight(enrollment)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_LOCKDOWN_MODE)

    def test_enrollment_preflight_with_an_out_of_scope_entry(self):
        configuration = force_configuration()
        enrollment = self.force_enrollment(configuration)
        self.force_scoped_client_mode(configuration, lockdown=True, serial_numbers=["9876543210"])
        response = self.enrollment_preflight(enrollment)
        self.assertEqual(response["client_mode"], Configuration.PREFLIGHT_MONITOR_MODE)

    # serialization

    def test_serialize_for_event(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        scm = self.force_scoped_client_mode(configuration, name="yolo", lockdown=True,
                                            serial_numbers=["0123456789"], tags=[tag])
        d = scm.serialize_for_event()
        self.assertEqual(d["name"], "yolo")
        self.assertEqual(d["client_mode"], "Lockdown")
        self.assertEqual(d["event_detail_source"], "INHERIT")
        self.assertEqual(d["serial_numbers"], ["0123456789"])
        self.assertEqual(d["tags"], [tag.serialize_for_event(keys_only=True)])
        self.assertEqual(scm.serialize_for_event(keys_only=True), {"pk": scm.pk, "name": "yolo"})

    def test_linked_objects_keys_for_event(self):
        configuration = force_configuration()
        scm = self.force_scoped_client_mode(configuration)
        self.assertEqual(scm.linked_objects_keys_for_event(),
                         {"santa_configuration": ((configuration.pk,),)})
