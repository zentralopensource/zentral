import threading
import uuid
from django.db import connection, connections, transaction
from django.db.models import F
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import (Configuration, EnrolledMachine, Enrollment,
                                          MachineRule, Rule, Target)
from zentral.contrib.santa.forms import test_cdhash, test_signing_id_identifier
from .utils import new_cdhash, new_sha256, new_team_id, new_signing_id_identifier


class SantaRuleEngineTestCase(TestCase):
    maxDiff = None

    @classmethod
    def setUpTestData(cls):
        cls.configuration = Configuration.objects.create(name=get_random_string(256), batch_size=5)
        cls.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        cls.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=cls.meta_business_unit)
        cls.enrollment = Enrollment.objects.create(configuration=cls.configuration,
                                                   secret=cls.enrollment_secret)
        cls.machine_serial_number = get_random_string(64)
        cls.enrolled_machine = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                              hardware_uuid=uuid.uuid4(),
                                                              serial_number=cls.machine_serial_number,
                                                              client_mode=Configuration.MONITOR_MODE,
                                                              santa_version="2022.1")
        cls.machine_serial_number2 = get_random_string(64)
        cls.enrolled_machine2 = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                               hardware_uuid=uuid.uuid4(),
                                                               serial_number=cls.machine_serial_number2,
                                                               client_mode=Configuration.MONITOR_MODE,
                                                               santa_version="2022.1")

    # utils

    def create_rule(self, target_type=Target.Type.BINARY, policy=Rule.Policy.ALLOWLIST, configuration=None):
        if target_type == Target.Type.TEAM_ID:
            identifier = new_team_id()
        elif target_type == Target.Type.SIGNING_ID:
            identifier = new_signing_id_identifier()
        elif target_type == Target.Type.CDHASH:
            identifier = new_cdhash()
        else:
            identifier = new_sha256()
        target = Target.objects.create(type=target_type, identifier=identifier)
        if configuration is None:
            configuration = self.configuration
        rule = Rule.objects.create(configuration=configuration, target=target, policy=policy)
        return target, rule

    def create_and_serialize_for_iter_rule(
        self,
        target_type=Target.Type.BINARY,
        policy=Rule.Policy.ALLOWLIST,
        configuration=None
    ):
        target, rule = self.create_rule(target_type, policy, configuration)
        result = {
            "target_id": target.pk,
            "policy": rule.policy,
            "cel_expr": "",
            "rule_type": target.type,
            "identifier": target.identifier,
            "custom_msg": "",
            "custom_url": "",
            "version": rule.version,
        }
        return target, rule, result

    def commit_session(self):
        """The client confirmed the rules of the session with a postflight"""
        self.enrolled_machine.refresh_from_db()
        MachineRule.objects.commit_session(self.enrolled_machine, False)

    def force_batch_size_one_machine(self):
        configuration = Configuration.objects.create(name=get_random_string(32), batch_size=1)
        enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        enrollment = Enrollment.objects.create(configuration=configuration, secret=enrollment_secret)
        return EnrolledMachine.objects.create(enrollment=enrollment,
                                              hardware_uuid=uuid.uuid4(),
                                              serial_number=get_random_string(64),
                                              client_mode=Configuration.MONITOR_MODE,
                                              santa_version="2024.5")

    def create_ordered_rules(self, configuration):
        # identifiers chosen so that the rules always come in this order
        rules = []
        for identifier in ("0" * 63 + "a", "f" * 64):
            target = Target.objects.create(type=Target.Type.BINARY, identifier=identifier)
            rules.append(Rule.objects.create(configuration=configuration, target=target,
                                             policy=Rule.Policy.ALLOWLIST))
        return rules

    def create_and_serialize_rule(
        self,
        target_type=Target.Type.BINARY,
        policy=Rule.Policy.ALLOWLIST,
        configuration=None
    ):
        target, rule = self.create_rule(target_type, policy, configuration)
        serialized_rule = {
            "rule_type": target.type,
            "identifier": target.identifier,
            "policy": rule.policy.name,
        }
        if rule.cel_expr:
            serialized_rule["cel_expr"] = rule.cel_expr
        if rule.custom_msg:
            serialized_rule["custom_msg"] = rule.custom_msg
        return target, rule, serialized_rule

    # tests

    def test_cdhash_identifier(self):
        for identifier, result in (("platform:com.apple.curl", False),
                                   ("yolo", False),
                                   ("EQHXZ8M8AV:com.google.Chrome", False),
                                   ("575bc039ebf67a3fd686a14d5d1bc569ec7ba18e", True)):
            self.assertEqual(test_cdhash(identifier), result)

    def test_sining_id_identifier(self):
        for identifier, result in (("platform:com.apple.curl", True),
                                   ("yolo", False),
                                   ("yolo:com.apple.curl", False),
                                   ("EQHXZ8M8AV:com.google.Chrome", True),
                                   ("EQHXZ8M8AV:chrome_crashpad_handler", True),
                                   ("EQHXZ8M8AV:not-a-thing", True),
                                   ("94KV3E626L:Frameworks[]Electron Framework", True),
                                   ("EQHXZ8M8AV", False)):
            self.assertEqual(test_signing_id_identifier(identifier), result)

    def test_no_rule_sync_ok(self):
        self.assertTrue(self.enrolled_machine.sync_ok())
        self.assertTrue(self.enrolled_machine2.sync_ok())

    def test_transitive_rules_sync_ok(self):
        # the transitive rules are created by the client and reported as binary rules
        for i in range(3):
            target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=Target.Type.BINARY)
            MachineRule.objects.create(
                enrolled_machine=self.enrolled_machine,
                target=target,
                policy=rule.policy,
                version=rule.version,
                cursor=None
            )
        self.enrolled_machine.binary_rule_count = 3 + 17
        self.enrolled_machine.transitive_rule_count = 17
        self.assertTrue(self.enrolled_machine.sync_ok())

    def test_transitive_rules_missing_synced_binary_sync_not_ok(self):
        for i in range(3):
            target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=Target.Type.BINARY)
            if i == 0:
                continue
            MachineRule.objects.create(
                enrolled_machine=self.enrolled_machine,
                target=target,
                policy=rule.policy,
                version=rule.version,
                cursor=None
            )
        self.enrolled_machine.binary_rule_count = 3 + 17
        self.enrolled_machine.transitive_rule_count = 17
        self.assertFalse(self.enrolled_machine.sync_ok())

    def test_multiple_rules_missing_reported_teamid_sync_not_ok(self):
        for target_type, count in ((Target.Type.BINARY, 3), (Target.Type.CERTIFICATE, 2), (Target.Type.TEAM_ID, 1)):
            for i in range(count):
                # create rule
                target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=target_type)
                # sync rule
                MachineRule.objects.create(
                    enrolled_machine=self.enrolled_machine,
                    target=target,
                    policy=rule.policy,
                    version=rule.version,
                    cursor=None
                )
        self.enrolled_machine.binary_rule_count = 3
        self.enrolled_machine.certificate_rule_count = 2
        self.enrolled_machine.signingid_rule_count = 0
        self.enrolled_machine.teamid_rule_count = 0
        self.assertFalse(self.enrolled_machine.sync_ok())

    def test_multiple_rules_missing_synced_certificate_sync_not_ok(self):
        for target_type, count in ((Target.Type.BINARY, 3), (Target.Type.CERTIFICATE, 2), (Target.Type.TEAM_ID, 1)):
            for i in range(count):
                # create rule
                target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=target_type)
                # sync rule
                if target_type == Target.Type.CERTIFICATE:
                    continue
                MachineRule.objects.create(
                    enrolled_machine=self.enrolled_machine,
                    target=target,
                    policy=rule.policy,
                    version=rule.version,
                    cursor=None
                )
        self.enrolled_machine.binary_rule_count = 3
        self.enrolled_machine.cdhash_rule_count = 0
        self.enrolled_machine.certificate_rule_count = 2
        self.enrolled_machine.signingid_rule_count = 0
        self.enrolled_machine.teamid_rule_count = 1
        self.assertFalse(self.enrolled_machine.sync_ok())

    def test_multiple_rules_missing_cdhash_sync_not_ok(self):
        for target_type, count in ((Target.Type.BINARY, 2), (Target.Type.CDHASH, 1),):
            for i in range(count):
                # create rule
                target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=target_type)
                # sync rule
                if target_type == Target.Type.CDHASH:
                    continue
                MachineRule.objects.create(
                    enrolled_machine=self.enrolled_machine,
                    target=target,
                    policy=rule.policy,
                    version=rule.version,
                    cursor=None
                )
        self.enrolled_machine.binary_rule_count = 2
        self.enrolled_machine.cdhash_rule_count = 1
        self.enrolled_machine.certificate_rule_count = 0
        self.enrolled_machine.signingid_rule_count = 0
        self.enrolled_machine.teamid_rule_count = 0
        self.assertFalse(self.enrolled_machine.sync_ok())

    def test_multiple_rules_cursor_sync_not_ok(self):
        for target_type, count in ((Target.Type.BINARY, 4),
                                   (Target.Type.CDHASH, 3),
                                   (Target.Type.CERTIFICATE, 2),
                                   (Target.Type.TEAM_ID, 1)):
            for i in range(count):
                # create rule
                target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=target_type)
                # sync rule
                MachineRule.objects.create(
                    enrolled_machine=self.enrolled_machine,
                    target=target,
                    policy=rule.policy,
                    version=rule.version,
                    cursor=get_random_string(8) if target_type == Target.Type.BINARY else None,
                    sync_session=get_random_string(8) if target_type == Target.Type.BINARY else None
                )
        self.enrolled_machine.binary_rule_count = 4
        self.enrolled_machine.cdhash_rule_count = 3
        self.enrolled_machine.certificate_rule_count = 2
        self.enrolled_machine.signingid_rule_count = 0
        self.enrolled_machine.teamid_rule_count = 1
        self.assertFalse(self.enrolled_machine.sync_ok())

    def test_multiple_rules_sync_ok(self):
        for target_type, count in ((Target.Type.BINARY, 3),
                                   (Target.Type.CDHASH, 5),
                                   (Target.Type.CERTIFICATE, 2),
                                   (Target.Type.SIGNING_ID, 1),
                                   (Target.Type.TEAM_ID, 4)):
            for i in range(count):
                # create rule
                target, rule, _ = self.create_and_serialize_for_iter_rule(target_type=target_type)
                # sync rule
                MachineRule.objects.create(
                    enrolled_machine=self.enrolled_machine,
                    target=target,
                    policy=rule.policy,
                    version=rule.version,
                    cursor=None,
                )
        self.enrolled_machine.binary_rule_count = 3
        self.enrolled_machine.cdhash_rule_count = 5
        self.enrolled_machine.certificate_rule_count = 2
        self.enrolled_machine.signingid_rule_count = 1
        self.enrolled_machine.teamid_rule_count = 4
        self.assertTrue(self.enrolled_machine.sync_ok())

    def test_iter_new_rules(self):
        # create rule
        target, rule, result = self.create_and_serialize_for_iter_rule()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        # sync rule
        machine_rule = MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=get_random_string(8),
        )
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        # update rule
        rule.custom_msg = "New message"
        rule.version = F("version") + 1
        rule.save()
        rule.refresh_from_db()
        result2 = result.copy()
        result2["custom_msg"] = rule.custom_msg
        result2["version"] = 2
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result2])
        # delete rule
        rule.delete()
        result3 = result.copy()
        result3["policy"] = 4  # REMOVE
        result3.pop("cel_expr", None)
        result3.pop("custom_msg", None)
        result3.pop("custom_url", None)
        result3["version"] = 1
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result3])
        # sync rule
        machine_rule.delete()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])

    def test_iter_new_rules_second_machine(self):
        # create rule
        target, rule, result = self.create_and_serialize_for_iter_rule()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        # sync rule
        MachineRule.objects.create(
            enrolled_machine=self.enrolled_machine,
            target=target,
            policy=rule.policy,
            version=rule.version,
            cursor=get_random_string(8),
        )
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine2, [])), [result])

    def test_iter_serial_number_new_rules(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        rule.serial_numbers = [get_random_string(13)]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        rule.serial_numbers.append(self.enrolled_machine.serial_number)
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])

    def test_one_excluded_serial_number(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        rule.excluded_serial_numbers = [self.enrolled_machine.serial_number]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        rule.excluded_serial_numbers = [get_random_string(12)]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])

    def test_two_primary_user_machines_one_excluded_serial_number(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        primary_user = get_random_string(15)
        rule.primary_users.append(primary_user)
        rule.save()
        self.enrolled_machine.primary_user = primary_user
        self.enrolled_machine.save()
        self.enrolled_machine2.primary_user = primary_user
        self.enrolled_machine2.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine2, [])), [result])
        rule.excluded_serial_numbers = [self.enrolled_machine.serial_number]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine2, [])), [result])

    def test_iter_primary_user_new_rules(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        rule.primary_users = [get_random_string(14)]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        primary_user = get_random_string(15)
        rule.primary_users.append(primary_user)
        rule.save()
        self.enrolled_machine.primary_user = primary_user
        self.enrolled_machine.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])

    def test_one_excluded_primary_user(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        primary_user = get_random_string(12)
        rule.excluded_primary_users = [primary_user]
        rule.save()
        self.enrolled_machine.primary_user = primary_user
        self.enrolled_machine.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        rule.excluded_primary_users = [get_random_string(12)]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        # no rules if excluded_primary_users and the machine reports no primary user!!!
        self.enrolled_machine.primary_user = None
        self.enrolled_machine.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])

    def test_two_serial_number_machines_one_excluded_primary_user(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        rule.serial_numbers = [self.enrolled_machine.serial_number, self.enrolled_machine2.serial_number]
        rule.save()
        primary_user1 = get_random_string(15)
        self.enrolled_machine.primary_user = primary_user1
        self.enrolled_machine.save()
        primary_user2 = get_random_string(15)
        self.enrolled_machine2.primary_user = primary_user2
        self.enrolled_machine2.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine2, [])), [result])
        rule.excluded_primary_users = [primary_user1]
        rule.save()
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine2, [])), [result])

    def test_iter_tag_new_rules(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        rule.tags.set(tags)
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[0].pk])), [result])

    def test_one_excluded_tag(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(2)]
        rule.excluded_tags.set(tags[-1:])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[-1].pk])), [])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[0].pk])), [result])
        rule.excluded_tags.set([])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[-1].pk])), [result])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [result])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[0].pk])), [result])

    def test_primary_user_machine_two_tags_one_excluded_tag(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        primary_user = get_random_string(14)
        rule.primary_users = [primary_user]
        rule.save()
        self.enrolled_machine.primary_user = primary_user
        self.enrolled_machine.save()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        tag_pks = [t.pk for t in tags]
        rule.tags.set(tags[:-1])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, tag_pks)), [result])
        rule.excluded_tags.add(tags[-1])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, tag_pks)), [])

    def test_configuration_leakage(self):
        configuration2 = Configuration.objects.create(name=get_random_string(256))
        target, rule, _ = self.create_and_serialize_for_iter_rule(configuration=configuration2)
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])

    def test_one_next_rule(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        for _ in range(2):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
            # the last batch has no cursor, the client stops and sends the postflight
            self.assertIsNone(response_cursor)
            self.assertEqual(rule_batch, [serialized_rule])
            machine_rule_qs = self.enrolled_machine.machinerule_set.all()
            self.assertEqual(machine_rule_qs.count(), 1)
            machine_rule = machine_rule_qs.first()
            self.assertEqual(machine_rule.target, target)
            self.assertEqual(machine_rule.policy, rule.policy)
            self.assertEqual(machine_rule.version, rule.version)
            self.assertIsNotNone(machine_rule.cursor)

    def test_next_rule_batch_pagination(self):
        serialized_rules = []
        for _ in range(6):
            _, _, serialized_rule = self.create_and_serialize_rule()
            serialized_rules.append(serialized_rule)
        serialized_rules.sort(key=lambda r: r["identifier"])
        i = 0
        response_cursor = None
        for batch_len, last in ((5, False), (1, True)):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, [],
                response_cursor
            )
            self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
            i += batch_len
            if last:
                # no extra round trip to acknowledge the last batch
                self.assertIsNone(response_cursor)
            else:
                self.assertIsNotNone(response_cursor)
                self.assertEqual(MachineRule.objects.filter(enrolled_machine=self.enrolled_machine,
                                                            cursor=response_cursor).count(),
                                 batch_len)
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        self.assertEqual(machine_rule_qs.count(), 6)
        # the last batch is only acknowledged by the postflight
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
        self.enrolled_machine.refresh_from_db()
        MachineRule.objects.commit_session(self.enrolled_machine, False)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 6)

    def test_lost_response_batch_pagination(self):
        serialized_rules = []
        for _ in range(11):
            _, _, serialized_rule = self.create_and_serialize_rule()
            serialized_rules.append(serialized_rule)
        serialized_rules.sort(key=lambda r: r["identifier"])
        response_cursor = None
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        i = 0
        # first client request, first 5 rules
        batch_len = 5
        rule_batch, response_cursor1 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor
        )
        self.assertIsNotNone(response_cursor1)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 0)
        self.assertEqual(machine_rule_qs.filter(cursor=response_cursor1).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).exclude(cursor=response_cursor1).count(), 0)
        self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
        i += batch_len
        # second client request, next 5 rules
        rule_batch, response_cursor2 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor1
        )
        self.assertIsNotNone(response_cursor2)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor=response_cursor2).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).exclude(cursor=response_cursor2).count(), 0)
        self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
        i += batch_len
        # third client request, with first cursor.
        # the client has never received a response for the second request, and is retrying it.
        i -= batch_len
        rule_batch, response_cursor3 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor1
        )
        self.assertIsNotNone(response_cursor3)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor=response_cursor3).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).exclude(cursor=response_cursor3).count(), 0)
        self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
        i += batch_len
        # the client received the last batch, it is not sent a cursor and stops there
        batch_len = 1
        rule_batch, response_cursor4 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor3
        )
        self.assertIsNone(response_cursor4)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 10)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).count(), batch_len)
        self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
        # the postflight acknowledges the last batch
        self.enrolled_machine.refresh_from_db()
        MachineRule.objects.commit_session(self.enrolled_machine, False)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 11)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).count(), 0)

    def test_reset_batch_pagination(self):
        serialized_rules = []
        for _ in range(6):
            _, _, serialized_rule = self.create_and_serialize_rule()
            serialized_rules.append(serialized_rule)
        serialized_rules.sort(key=lambda r: r["identifier"])
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        # first 2 requests OK
        i = 0
        response_cursor = None
        for batch_len, last in ((5, False), (1, True)):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, [],
                response_cursor
            )
            self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
            i += batch_len
            if last:
                self.assertIsNone(response_cursor)
            else:
                self.assertIsNotNone(response_cursor)
                self.assertEqual(machine_rule_qs.filter(cursor=response_cursor).count(), batch_len)
        self.assertEqual(machine_rule_qs.count(), 6)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
        # the session is lost before the postflight, the client keeps making new requests
        # without cursor and getting the last unacknowlegded rule
        for _ in range(2):
            rule_batch, response_cursor_post_reset = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, []
            )
            self.assertIsNone(response_cursor_post_reset)
            self.assertEqual(rule_batch, [serialized_rules[-1]])
            self.assertEqual(machine_rule_qs.count(), 6)
            self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
            self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).count(), 1)
        # the client confirms the session
        self.enrolled_machine.refresh_from_db()
        MachineRule.objects.commit_session(self.enrolled_machine, False)
        self.assertEqual(machine_rule_qs.count(), 6)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 6)

    def test_updated_rule(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.commit_session()
        rule.custom_msg = "YOLO"
        rule.version = F("version") + 1
        rule.save()
        serialized_rule["custom_msg"] = rule.custom_msg
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        # the update is the last batch, the client stops there
        self.assertIsNone(response_cursor)
        self.assertEqual(rule_batch, [serialized_rule])
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        self.assertEqual(machine_rule_qs.count(), 1)
        machine_rule = machine_rule_qs.first()
        self.assertEqual(machine_rule.target, target)
        self.assertEqual(machine_rule.policy, rule.policy)
        self.assertEqual(machine_rule.version, 2)
        # the rule the client still has is kept, this update only bumped the version
        self.assertEqual(machine_rule.committed_policy, rule.policy)
        self.assertEqual(machine_rule.committed_version, 1)
        self.commit_session()
        self.assertEqual(machine_rule_qs.count(), 1)
        self.assertEqual(machine_rule.pk, machine_rule_qs.first().pk)
        machine_rule.refresh_from_db()
        self.assertIsNone(machine_rule.cursor)
        # the client confirmed the update, there is no other version of the rule anymore
        self.assertIsNone(machine_rule.committed_policy)
        self.assertIsNone(machine_rule.committed_version)
        rule_batch2, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch2, [])
        self.assertEqual(response_cursor, None)

    def test_deleted_rule(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        rule_policy = rule.policy
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.commit_session()
        rule.delete()
        serialized_rule.pop("custom_msg", None)
        serialized_rule["policy"] = "REMOVE"
        for _ in range(2):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
            self.enrolled_machine.refresh_from_db()
            # the removal is the last batch, the client stops there
            self.assertIsNone(response_cursor)
            self.assertEqual(rule_batch, [serialized_rule])
            machine_rule_qs = self.enrolled_machine.machinerule_set.all()
            self.assertEqual(machine_rule_qs.count(), 1)
            machine_rule = machine_rule_qs.first()
            self.assertEqual(machine_rule.target, target)
            # the removal is staged, the ledger keeps the rule the client has
            self.assertTrue(machine_rule.staged_removal)
            self.assertEqual(machine_rule.policy, rule_policy)
            self.assertEqual(machine_rule.committed_policy, rule_policy)
            self.assertEqual(machine_rule.committed_version, 1)
            self.assertIsNotNone(machine_rule.cursor)
        # the machine rule is only removed from the ledger once the client confirms the session
        self.assertEqual(machine_rule_qs.count(), 1)
        self.commit_session()
        self.assertEqual(machine_rule_qs.count(), 0)

    def test_scoped_rule(self):
        # rule without restrictions
        target, rule, serialized_rule = self.create_and_serialize_rule()
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.commit_session()
        # scope rule with some tags
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(4)]
        rule.tags.set(tags[:-1])
        rule.excluded_tags.set(tags[-2:-1])
        # rule not in scope anymore, needs to be removed
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        serialized_remove_rule = serialized_rule.copy()
        serialized_remove_rule.pop("custom_msg", None)
        serialized_remove_rule["policy"] = "REMOVE"
        self.assertEqual(rule_batch, [serialized_remove_rule])
        self.commit_session()
        # rule removed, noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, [])
        # machine tagged, rule needs to be added
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk])
        self.assertEqual(rule_batch, [serialized_rule])
        self.commit_session()
        # rule added, noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk])
        self.assertEqual(rule_batch, [])
        # rule again not in scope, needs to be removed
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine,
                                                                              [tags[0].pk, tags[-2].pk])
        serialized_remove_rule = serialized_rule.copy()
        serialized_remove_rule.pop("custom_msg", None)
        serialized_remove_rule["policy"] = "REMOVE"
        self.assertEqual(rule_batch, [serialized_remove_rule])
        self.commit_session()
        # rule removed, noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [])
        rule.tags.set([])
        rule.excluded_tags.set(tags[-1:])
        # rule again in scope, rule needs to be added
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine,
                                                                              [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [serialized_rule])
        self.commit_session()
        # rule added noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [])

    # discarding a session

    def test_discard_session_does_not_delete_the_removal_it_restored(self):
        # the restored rows must not feed the delete statements, whatever the statement order
        removal_target, _ = self.create_rule()
        addition_target, _ = self.create_rule()
        removal = MachineRule.objects.create(enrolled_machine=self.enrolled_machine, target=removal_target,
                                             policy=Rule.Policy.ALLOWLIST, version=1,
                                             sync_session="session1", staged_removal=True,
                                             committed_policy=Rule.Policy.ALLOWLIST,
                                             committed_version=1)
        addition = MachineRule.objects.create(enrolled_machine=self.enrolled_machine, target=addition_target,
                                              policy=Rule.Policy.ALLOWLIST, version=1,
                                              sync_session="session1")
        counts = MachineRule.objects.discard_session(self.enrolled_machine)
        self.assertEqual(counts, {"rules_discarded": 1, "removals_discarded": 0,
                                  "rules_restored": 0, "removals_restored": 1})
        # the client still holds the rule, the removal is committed again and sent again next session
        removal.refresh_from_db()
        self.assertIsNone(removal.sync_session)
        self.assertIsNone(removal.cursor)
        self.assertFalse(removal.staged_removal)
        self.assertEqual(removal.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(removal.version, 1)
        self.assertIsNone(removal.committed_policy)
        self.assertIsNone(removal.committed_version)
        # the staged rule only existed because of the session
        self.assertEqual(MachineRule.objects.filter(pk=addition.pk).count(), 0)

    def test_discard_session_restores_the_rule_the_client_confirmed(self):
        target, _ = self.create_rule()
        replacement = MachineRule.objects.create(enrolled_machine=self.enrolled_machine, target=target,
                                                 policy=Rule.Policy.BLOCKLIST, version=2,
                                                 sync_session="session1",
                                                 committed_policy=Rule.Policy.ALLOWLIST,
                                                 committed_version=1)
        counts = MachineRule.objects.discard_session(self.enrolled_machine)
        self.assertEqual(counts, {"rules_discarded": 0, "removals_discarded": 0,
                                  "rules_restored": 1, "removals_restored": 0})
        # the client still holds the rule the session replaced, and it is sent again next session
        replacement.refresh_from_db()
        self.assertIsNone(replacement.sync_session)
        self.assertIsNone(replacement.cursor)
        self.assertEqual(replacement.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(replacement.version, 1)
        self.assertIsNone(replacement.committed_policy)
        self.assertIsNone(replacement.committed_version)

    def test_discard_session_discards_the_removal_of_a_rule_of_the_same_session(self):
        target, _ = self.create_rule()
        removal = MachineRule.objects.create(enrolled_machine=self.enrolled_machine, target=target,
                                             policy=Rule.Policy.ALLOWLIST, version=1,
                                             sync_session="session1", staged_removal=True)
        counts = MachineRule.objects.discard_session(self.enrolled_machine)
        self.assertEqual(counts, {"rules_discarded": 0, "removals_discarded": 1,
                                  "rules_restored": 0, "removals_restored": 0})
        # the removal covered a rule staged during the same session: the client holds nothing
        self.assertEqual(MachineRule.objects.filter(pk=removal.pk).count(), 0)

    # rolling back an unacknowledged batch

    def test_unstage_goes_back_to_the_rule_a_removal_of_the_same_session_covered(self):
        target, _ = self.create_rule()
        removal = MachineRule.objects.create(enrolled_machine=self.enrolled_machine, target=target,
                                             policy=Rule.Policy.ALLOWLIST, version=1,
                                             cursor="cursor01", sync_session="session1", staged_removal=True)
        MachineRule.objects._unstage(MachineRule.objects.filter(pk=removal.pk))
        # back to the rule staged by the acknowledged batch, so that the removal is sent again
        removal.refresh_from_db()
        self.assertEqual(removal.sync_session, "session1")
        self.assertIsNone(removal.cursor)
        self.assertFalse(removal.staged_removal)
        self.assertEqual(removal.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(removal.version, 1)
        self.assertIsNone(removal.committed_policy)
        self.assertIsNone(removal.committed_version)

    # a session that removes a rule it staged itself

    def test_discarded_session_forgets_the_removal_of_a_rule_it_staged(self):
        enrolled_machine = self.force_batch_size_one_machine()
        added_rule, _ = self.create_ordered_rules(enrolled_machine.enrollment.configuration)
        added_target = added_rule.target
        # the rule is staged by the first batch, acknowledged by the second request
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        self.assertEqual([r["identifier"] for r in rule_batch], [added_target.identifier])
        # the rule is deleted before the next batch, which stages its removal
        added_rule.delete()
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], response_cursor)
        self.assertEqual(rule_batch, [{"rule_type": Target.Type.BINARY,
                                       "identifier": added_target.identifier,
                                       "policy": "REMOVE"}])
        machine_rule = MachineRule.objects.get(enrolled_machine=enrolled_machine, target=added_target)
        self.assertTrue(machine_rule.staged_removal)
        # the removal covers a rule of the same session: the client holds nothing
        self.assertIsNone(machine_rule.committed_policy)
        self.assertIsNone(machine_rule.committed_version)
        # the client never confirms the session
        counts = MachineRule.objects.discard_session(enrolled_machine)
        self.assertEqual(counts, {"rules_discarded": 0, "removals_discarded": 1,
                                  "rules_restored": 0, "removals_restored": 0})
        self.assertEqual(MachineRule.objects.filter(enrolled_machine=enrolled_machine).count(), 0)
        # the rule is created again: the client never held it, it must be sent
        Rule.objects.create(configuration=enrolled_machine.enrollment.configuration,
                            target=added_target, policy=Rule.Policy.ALLOWLIST)
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        self.assertEqual([(r["identifier"], r["policy"]) for r in rule_batch],
                         [(added_target.identifier, "ALLOWLIST")])

    def test_committed_session_confirms_the_removal_of_a_rule_it_staged(self):
        enrolled_machine = self.force_batch_size_one_machine()
        added_rule, other_rule = self.create_ordered_rules(enrolled_machine.enrollment.configuration)
        _, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        # the rule of the first batch is deleted, the second batch stages its removal
        added_rule.delete()
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                              response_cursor)
        self.assertEqual([r["policy"] for r in rule_batch], ["REMOVE"])
        # the last batch, with the second rule
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                              response_cursor)
        self.assertEqual([r["identifier"] for r in rule_batch], [other_rule.target.identifier])
        self.assertIsNone(response_cursor)
        # the client applied the rule, then its removal: it holds nothing for the first target
        counts = MachineRule.objects.commit_session(enrolled_machine, False)
        self.assertEqual(counts, {"rules_committed": 1, "removals_confirmed": 1, "rules_dropped": 0})
        machine_rule = MachineRule.objects.get(enrolled_machine=enrolled_machine)
        self.assertEqual(machine_rule.target, other_rule.target)
        self.assertIsNone(machine_rule.sync_session)

    def test_lost_batch_sends_the_removal_of_a_rule_of_the_same_session_again(self):
        enrolled_machine = self.force_batch_size_one_machine()
        added_rule, _ = self.create_ordered_rules(enrolled_machine.enrollment.configuration)
        _, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        added_rule.delete()
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], response_cursor)
        self.assertEqual([r["policy"] for r in rule_batch], ["REMOVE"])
        # the batch is lost, the client asks for it again with the same cursor
        rule_batch_again, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], response_cursor)
        self.assertEqual(rule_batch_again, rule_batch)
        machine_rule = MachineRule.objects.get(enrolled_machine=enrolled_machine, target=added_rule.target)
        self.assertTrue(machine_rule.staged_removal)
        self.assertIsNone(machine_rule.committed_policy)
        # the client applied the rule, then its removal
        counts = MachineRule.objects.commit_session(enrolled_machine, False)
        self.assertEqual(counts["removals_confirmed"], 1)
        self.assertEqual(MachineRule.objects.filter(enrolled_machine=enrolled_machine).count(), 0)

    # a session that removes a rule it had already replaced

    def test_discarded_session_restores_the_rule_it_replaced_then_removed(self):
        enrolled_machine = self.force_batch_size_one_machine()
        configuration = enrolled_machine.enrollment.configuration
        replaced_rule, _ = self.create_ordered_rules(configuration)
        replaced_target = replaced_rule.target
        # the client confirms the two rules
        response_cursor = None
        for _ in range(2):
            _, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                         response_cursor)
        MachineRule.objects.commit_session(enrolled_machine, False)
        # the rules are updated. The first one is staged by the first batch of a new session,
        # then deleted, and the second batch stages its removal
        Rule.objects.filter(configuration=configuration).update(version=F("version") + 1)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        self.assertEqual([r["identifier"] for r in rule_batch], [replaced_target.identifier])
        replaced_rule.delete()
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], response_cursor)
        self.assertEqual([r["policy"] for r in rule_batch], ["REMOVE"])
        machine_rule = MachineRule.objects.get(enrolled_machine=enrolled_machine, target=replaced_target)
        self.assertTrue(machine_rule.staged_removal)
        # the ledger keeps the rule the client confirmed
        self.assertEqual(machine_rule.committed_policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(machine_rule.committed_version, 1)
        # the client never confirms the session
        counts = MachineRule.objects.discard_session(enrolled_machine)
        self.assertEqual(counts, {"rules_discarded": 0, "removals_discarded": 0,
                                  "rules_restored": 0, "removals_restored": 1})
        machine_rule.refresh_from_db()
        self.assertIsNone(machine_rule.sync_session)
        self.assertFalse(machine_rule.staged_removal)
        self.assertEqual(machine_rule.policy, Rule.Policy.ALLOWLIST)
        self.assertEqual(machine_rule.version, 1)
        # the rule is still gone from the configuration: the removal is sent again
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        self.assertEqual([(r["identifier"], r["policy"]) for r in rule_batch],
                         [(replaced_target.identifier, "REMOVE")])

    def test_committed_session_confirms_the_removal_of_a_rule_it_replaced(self):
        enrolled_machine = self.force_batch_size_one_machine()
        configuration = enrolled_machine.enrollment.configuration
        replaced_rule, other_rule = self.create_ordered_rules(configuration)
        replaced_target = replaced_rule.target
        # the client confirms the two rules
        response_cursor = None
        for _ in range(2):
            _, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                         response_cursor)
        MachineRule.objects.commit_session(enrolled_machine, False)
        # the rules are updated. The first one is staged by the first batch of a new session,
        # then deleted, and the second batch stages its removal
        Rule.objects.filter(configuration=configuration).update(version=F("version") + 1)
        _, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [])
        replaced_rule.delete()
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                              response_cursor)
        self.assertEqual([r["policy"] for r in rule_batch], ["REMOVE"])
        # the update of the second rule, last batch
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(enrolled_machine, [],
                                                                              response_cursor)
        self.assertEqual([r["identifier"] for r in rule_batch], [other_rule.target.identifier])
        self.assertIsNone(response_cursor)
        # the client applied the update, then the removal: it holds nothing for the target
        counts = MachineRule.objects.commit_session(enrolled_machine, False)
        self.assertEqual(counts, {"rules_committed": 1, "removals_confirmed": 1, "rules_dropped": 0})
        self.assertEqual(MachineRule.objects.filter(enrolled_machine=enrolled_machine,
                                                    target=replaced_target).count(), 0)

    def assertMachineLockTaken(self, ctx, taken=True):
        lock_queries = [
            q["sql"] for q in ctx.captured_queries
            if "santa_enrolledmachine" in q["sql"] and "FOR UPDATE" in q["sql"]
        ]
        if taken:
            self.assertTrue(lock_queries)
        else:
            self.assertEqual(lock_queries, [])

    def test_get_next_rule_batch_takes_the_machine_lock(self):
        self.create_rule()
        with CaptureQueriesContext(connection) as ctx:
            MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertMachineLockTaken(ctx)

    def test_commit_session_takes_the_machine_lock(self):
        self.create_rule()
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.enrolled_machine.refresh_from_db()
        with CaptureQueriesContext(connection) as ctx:
            MachineRule.objects.commit_session(self.enrolled_machine, False)
        self.assertMachineLockTaken(ctx)

    def test_discard_session_takes_the_machine_lock(self):
        with CaptureQueriesContext(connection) as ctx:
            MachineRule.objects.discard_session(self.enrolled_machine)
        self.assertMachineLockTaken(ctx)

    def test_reconcile_sync_session_takes_the_machine_lock(self):
        self.enrolled_machine.start_sync_session(False)
        with CaptureQueriesContext(connection) as ctx:
            self.enrolled_machine.reconcile_sync_session()
        self.assertMachineLockTaken(ctx)

    def test_reconcile_without_session_does_not_take_the_machine_lock(self):
        # the common preflight path, without a dangling session, must stay lock free
        with CaptureQueriesContext(connection) as ctx:
            self.enrolled_machine.reconcile_sync_session()
        self.assertMachineLockTaken(ctx, taken=False)

    def test_rule_download_stages_under_the_current_row_session(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        # a concurrent preflight started a session after the request loaded the machine
        sync_session = get_random_string(8)
        EnrolledMachine.objects.filter(pk=self.enrolled_machine.pk).update(
            sync_session=sync_session, sync_session_clean=False
        )
        self.assertIsNone(self.enrolled_machine.sync_session)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, [serialized_rule])
        self.assertIsNone(response_cursor)
        machine_rule = self.enrolled_machine.machinerule_set.get()
        self.assertEqual(machine_rule.sync_session, sync_session)
        # the row session was adopted, not replaced
        self.enrolled_machine.refresh_from_db()
        self.assertEqual(self.enrolled_machine.sync_session, sync_session)


class SantaRuleEngineConcurrencyTestCase(TransactionTestCase):
    def setUp(self):
        self.configuration = Configuration.objects.create(name=get_random_string(256), batch_size=2)
        self.meta_business_unit = MetaBusinessUnit.objects.create(name=get_random_string(64))
        self.enrollment_secret = EnrollmentSecret.objects.create(meta_business_unit=self.meta_business_unit)
        self.enrollment = Enrollment.objects.create(configuration=self.configuration,
                                                    secret=self.enrollment_secret)
        self.enrolled_machine = EnrolledMachine.objects.create(enrollment=self.enrollment,
                                                               hardware_uuid=uuid.uuid4(),
                                                               serial_number=get_random_string(64),
                                                               client_mode=Configuration.MONITOR_MODE,
                                                               santa_version="2024.5")
        self.identifiers = set()
        for _ in range(5):
            target = Target.objects.create(type=Target.Type.BINARY, identifier=new_sha256())
            Rule.objects.create(configuration=self.configuration, target=target, policy=Rule.Policy.ALLOWLIST)
            self.identifiers.add(target.identifier)

    def test_duplicate_rule_download_regenerates_the_in_flight_batch(self):
        # santa retries a rule download with the same cursor after 30s. The retry must wait for
        # the in-flight request and send its batch again: without the machine lock, it could not
        # see the uncommitted staging, and skipped the batch for good.
        with transaction.atomic():
            batch1, cursor1 = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(len(batch1), 2)
        staged = threading.Event()
        release = threading.Event()
        results = {}

        def original_request():
            # the in-flight request for cursor1, stalled after staging the second batch
            try:
                enrolled_machine = EnrolledMachine.objects.get(pk=self.enrolled_machine.pk)
                with transaction.atomic():
                    results["original"] = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], cursor1)
                    staged.set()
                    release.wait(timeout=10)
            except Exception as exception:
                results["original_error"] = exception
            finally:
                staged.set()
                connections.close_all()

        def retried_request():
            # the client timed out on the original request, and retries it with the same cursor
            try:
                staged.wait(timeout=10)
                enrolled_machine = EnrolledMachine.objects.get(pk=self.enrolled_machine.pk)
                with transaction.atomic():
                    results["retry"] = MachineRule.objects.get_next_rule_batch(enrolled_machine, [], cursor1)
            except Exception as exception:
                results["retry_error"] = exception
            finally:
                connections.close_all()

        original = threading.Thread(target=original_request)
        retry = threading.Thread(target=retried_request)
        original.start()
        retry.start()
        # give the retry the time to block on the machine lock before releasing the original
        retry.join(timeout=1)
        self.assertTrue(retry.is_alive(), "the retry did not wait for the in-flight request")
        release.set()
        original.join(timeout=10)
        retry.join(timeout=10)
        self.assertFalse(original.is_alive())
        self.assertFalse(retry.is_alive())
        self.assertIsNone(results.get("original_error"))
        self.assertIsNone(results.get("retry_error"))
        original_batch, _ = results["original"]
        retry_batch, retry_cursor = results["retry"]
        # the retry sent the second batch again, it did not skip to the third one
        self.assertEqual([r["identifier"] for r in retry_batch],
                         [r["identifier"] for r in original_batch])
        self.assertIsNotNone(retry_cursor)
        with transaction.atomic():
            batch3, cursor3 = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], retry_cursor)
        self.assertEqual(len(batch3), 1)
        self.assertIsNone(cursor3)
        # the client received every rule exactly once
        received = [r["identifier"] for r in batch1 + retry_batch + batch3]
        self.assertEqual(len(received), 5)
        self.assertEqual(set(received), self.identifiers)
        self.enrolled_machine.refresh_from_db()
        with transaction.atomic():
            session_result = MachineRule.objects.commit_session(self.enrolled_machine, False)
        self.assertEqual(session_result["rules_committed"], 5)
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        self.assertEqual(machine_rule_qs.count(), 5)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True, sync_session__isnull=True).count(), 5)
