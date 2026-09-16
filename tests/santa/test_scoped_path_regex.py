import json
import uuid

from django.test import TestCase
from django.urls import reverse
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import Configuration, Enrollment, ScopedPathRegex
from .utils import force_configuration, force_enrolled_machine


class SantaScopedPathRegexTestCase(TestCase):
    def force_scoped_path_regex(self, configuration, regex, name=None, block=False, **kwargs):
        tags = kwargs.pop("tags", None)
        spr = ScopedPathRegex.objects.create(
            configuration=configuration,
            name=name or get_random_string(12),
            policy=ScopedPathRegex.Policy.BLOCK if block else ScopedPathRegex.Policy.ALLOW,
            regex=regex,
            **kwargs,
        )
        if tags:
            spr.tags.set(tags)
        return spr

    def enrolled_machine(self, configuration, serial_number="0123456789", primary_user=None, tags=None):
        return force_enrolled_machine(configuration=configuration, serial_number=serial_number,
                                      primary_user=primary_user, tags=tags, for_sync=True)

    def sync_config(self, configuration, **kwargs):
        return configuration.get_sync_server_config(self.enrolled_machine(configuration, **kwargs), (2022, 1))

    # composition

    def test_no_part_cannot_match(self):
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("", []),
                         Configuration.NON_MATCHING_PATH_REGEX)

    def test_baseline_only(self):
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("/usr/local/", []),
                         "^(?:(?:/usr/local/))")

    def test_entries_only(self):
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("", ["/a/", "/b/"]),
                         "^(?:(?:/a/)|(?:/b/))")

    def test_baseline_first(self):
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("/base/", ["/a/"]),
                         "^(?:(?:/base/)|(?:/a/))")

    def test_each_part_loses_its_own_anchor(self):
        # the union is anchored once, around every alternative
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("^/base/", ["^/a/", "/b/"]),
                         "^(?:(?:/base/)|(?:/a/)|(?:/b/))")

    def test_a_part_that_is_only_an_anchor_is_dropped(self):
        # "^" strips to "", and ICU compiles (?:) and matches it at position 0, which would
        # open the whole union to every path
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("^", ["/a/"]), "^(?:(?:/a/))")
        self.assertEqual(configuration.compose_path_regex("^", []),
                         Configuration.NON_MATCHING_PATH_REGEX)

    def test_a_union_that_does_not_compile_falls_back_to_the_configuration_pattern(self):
        # the pattern of the configuration is the one that was never validated, and dropping it
        # would end a block that works today
        configuration = force_configuration()
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR"):
            composed = configuration.compose_path_regex("(?i)/a/", ["/b/"])
        self.assertEqual(composed, "(?i)/a/")

    def test_a_union_that_does_not_compile_with_no_configuration_pattern(self):
        configuration = force_configuration()
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR"):
            composed = configuration.compose_path_regex("", ["(?i)/b/"])
        self.assertEqual(composed, Configuration.NON_MATCHING_PATH_REGEX)

    def test_an_icu_only_configuration_pattern_keeps_being_enforced(self):
        # \p{L} is valid ICU and not valid Python, and nothing validated it before this change
        configuration = force_configuration(blocked_path_regex=r"/Users/\p{L}+/Downloads/")
        self.force_scoped_path_regex(configuration, "/tmp/", name="a", block=True)
        with self.assertLogs("zentral.contrib.santa.models", level="ERROR"):
            config = self.sync_config(configuration)
        self.assertEqual(config["blocked_path_regex"], r"/Users/\p{L}+/Downloads/")

    def test_a_part_that_matches_an_empty_path_is_not_reachable(self):
        # the validator refuses these, the composition drops what strips to nothing
        configuration = force_configuration()
        self.assertEqual(configuration.compose_path_regex("^", ["/a/"]), "^(?:(?:/a/))")

    # preflight

    def test_no_entry_keeps_the_configuration_regexes(self):
        configuration = force_configuration(allowed_path_regex="/allowed/")
        config = self.sync_config(configuration)
        self.assertEqual(config["allowed_path_regex"], "^(?:(?:/allowed/))")
        self.assertEqual(config["blocked_path_regex"], Configuration.NON_MATCHING_PATH_REGEX)

    def test_entry_joins_the_configuration_regex(self):
        configuration = force_configuration(blocked_path_regex="/blocked/")
        self.force_scoped_path_regex(configuration, "/Users/[^/]+/Downloads/", name="a", block=True)
        config = self.sync_config(configuration)
        self.assertEqual(config["blocked_path_regex"],
                         "^(?:(?:/blocked/)|(?:/Users/[^/]+/Downloads/))")

    def test_the_policies_do_not_mix(self):
        configuration = force_configuration()
        self.force_scoped_path_regex(configuration, "/allowed/", name="a")
        self.force_scoped_path_regex(configuration, "/blocked/", name="b", block=True)
        config = self.sync_config(configuration)
        self.assertEqual(config["allowed_path_regex"], "^(?:(?:/allowed/))")
        self.assertEqual(config["blocked_path_regex"], "^(?:(?:/blocked/))")

    def test_entry_out_of_scope_is_not_composed(self):
        configuration = force_configuration()
        self.force_scoped_path_regex(configuration, "/a/", serial_numbers=["9876543210"])
        config = self.sync_config(configuration)
        self.assertEqual(config["allowed_path_regex"], Configuration.NON_MATCHING_PATH_REGEX)

    def test_entry_scoped_on_a_tag(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        self.force_scoped_path_regex(configuration, "/a/", tags=[tag])
        self.assertEqual(self.sync_config(configuration)["allowed_path_regex"],
                         Configuration.NON_MATCHING_PATH_REGEX)
        self.assertEqual(self.sync_config(configuration, tags=[tag])["allowed_path_regex"],
                         "^(?:(?:/a/))")

    def test_entry_of_another_configuration_is_not_composed(self):
        configuration = force_configuration()
        self.force_scoped_path_regex(force_configuration(), "/a/")
        self.assertEqual(self.sync_config(configuration)["allowed_path_regex"],
                         Configuration.NON_MATCHING_PATH_REGEX)

    # determinism — the client flushes every decision cache when the pattern changes

    def test_the_entries_are_composed_in_a_stable_order(self):
        configuration = force_configuration()
        for name in ("c", "a", "b"):
            self.force_scoped_path_regex(configuration, f"/{name}/", name=name)
        self.assertEqual(self.sync_config(configuration)["allowed_path_regex"],
                         "^(?:(?:/a/)|(?:/b/)|(?:/c/))")

    def test_updating_an_entry_does_not_reorder_the_union(self):
        configuration = force_configuration()
        for name in ("a", "b", "c"):
            self.force_scoped_path_regex(configuration, f"/{name}/", name=name)
        first = self.sync_config(configuration)["allowed_path_regex"]
        # an update moves the row in the heap, which is what an unordered read would follow
        spr = ScopedPathRegex.objects.get(configuration=configuration, name="a")
        spr.description = get_random_string(12)
        spr.save()
        self.assertEqual(self.sync_config(configuration)["allowed_path_regex"], first)

    # queries

    def test_no_entry_costs_no_query(self):
        configuration = force_configuration()
        machine = self.enrolled_machine(configuration)
        with self.assertNumQueries(0):
            configuration.get_sync_server_config(machine, (2022, 1))

    def test_one_query_for_the_entries(self):
        configuration = force_configuration()
        self.force_scoped_path_regex(configuration, "/a/")
        machine = self.enrolled_machine(configuration)
        # no tag prefetch: only the client mode ranks, and a path regex never does
        with self.assertNumQueries(1):
            configuration.get_sync_server_config(machine, (2022, 1))

    # serialization

    def test_serialize_for_event(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        spr = self.force_scoped_path_regex(configuration, "/a/", name="yolo", block=True,
                                           serial_numbers=["0123456789"], tags=[tag])
        d = spr.serialize_for_event()
        self.assertEqual(d["name"], "yolo")
        self.assertEqual(d["policy"], "BLOCK")
        self.assertEqual(d["regex"], "/a/")
        self.assertEqual(d["serial_numbers"], ["0123456789"])
        self.assertEqual(d["tags"], [tag.serialize_for_event(keys_only=True)])
        self.assertEqual(spr.serialize_for_event(keys_only=True), {"pk": spr.pk, "name": "yolo"})

    def test_linked_objects_keys_for_event(self):
        configuration = force_configuration()
        spr = self.force_scoped_path_regex(configuration, "/a/")
        self.assertEqual(spr.linked_objects_keys_for_event(),
                         {"santa_configuration": ((configuration.pk,),)})

    def test_get_absolute_url(self):
        configuration = force_configuration()
        spr = self.force_scoped_path_regex(configuration, "/a/")
        self.assertEqual(spr.get_absolute_url(),
                         configuration.get_absolute_url() + f"#scoped-path-regex-{spr.pk}")

    # preflight view

    def force_enrollment(self, configuration, tags=None):
        mbu = MetaBusinessUnit.objects.create(name=get_random_string(64))
        secret = EnrollmentSecret.objects.create(meta_business_unit=mbu)
        if tags:
            secret.tags.set(tags)
        return Enrollment.objects.create(configuration=configuration, secret=secret)

    def preflight(self, enrollment, hardware_uuid, serial_number):
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
        response = self.client.post(
            reverse("santa_public:preflight", args=(hardware_uuid,)),
            json.dumps(data), content_type="application/json",
            headers={"Zentral-Authorization": f"Bearer {enrollment.secret.secret}"},
        )
        self.assertEqual(response.status_code, 200)
        return response.json()

    def test_preflight_composes_the_entries(self):
        configuration = force_configuration()
        enrolled_machine = force_enrolled_machine(configuration=configuration)
        self.force_scoped_path_regex(configuration, "/a/", name="a", block=True)
        response = self.preflight(enrolled_machine.enrollment, enrolled_machine.hardware_uuid,
                                  enrolled_machine.serial_number)
        self.assertEqual(response["blocked_path_regex"], "^(?:(?:/a/))")

    def test_preflight_applies_an_entry_scoped_on_a_tag(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        enrolled_machine = force_enrolled_machine(configuration=configuration, tags=[tag])
        self.force_scoped_path_regex(configuration, "/a/", name="a", tags=[tag])
        response = self.preflight(enrolled_machine.enrollment, enrolled_machine.hardware_uuid,
                                  enrolled_machine.serial_number)
        self.assertEqual(response["allowed_path_regex"], "^(?:(?:/a/))")

    def test_enrollment_preflight_composes_the_entries(self):
        # the enrollment builds the machine without the annotations
        configuration = force_configuration()
        enrollment = self.force_enrollment(configuration)
        self.force_scoped_path_regex(configuration, "/a/", name="a", block=True)
        response = self.preflight(enrollment, uuid.uuid4(), get_random_string(12))
        self.assertEqual(response["blocked_path_regex"], "^(?:(?:/a/))")

    def test_enrollment_preflight_applies_an_enrollment_secret_tag(self):
        configuration = force_configuration()
        tag = Tag.objects.create(name=get_random_string(12))
        enrollment = self.force_enrollment(configuration, tags=[tag])
        self.force_scoped_path_regex(configuration, "/a/", name="a", tags=[tag])
        response = self.preflight(enrollment, uuid.uuid4(), get_random_string(12))
        self.assertEqual(response["allowed_path_regex"], "^(?:(?:/a/))")
