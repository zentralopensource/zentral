import uuid
from django.db.models import F
from django.test import TestCase
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
            "version": rule.version,
        }
        return target, rule, result

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
                    cursor=get_random_string(8) if target_type == Target.Type.BINARY else None
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
            self.assertIsNotNone(response_cursor)
            self.assertEqual(rule_batch, [serialized_rule])
            machine_rule_qs = self.enrolled_machine.machinerule_set.all()
            self.assertEqual(machine_rule_qs.count(), 1)
            machine_rule = machine_rule_qs.first()
            self.assertEqual(machine_rule.target, target)
            self.assertEqual(machine_rule.policy, rule.policy)
            self.assertEqual(machine_rule.version, rule.version)
            self.assertEqual(machine_rule.cursor, response_cursor)

    def test_next_rule_batch_pagination(self):
        serialized_rules = []
        for _ in range(6):
            _, _, serialized_rule = self.create_and_serialize_rule()
            serialized_rules.append(serialized_rule)
        serialized_rules.sort(key=lambda r: r["identifier"])
        i = 0
        response_cursor = None
        for batch_len in (5, 1):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, [],
                response_cursor
            )
            self.assertIsNotNone(response_cursor)
            self.assertEqual(MachineRule.objects.filter(enrolled_machine=self.enrolled_machine,
                                                        cursor=response_cursor).count(),
                             batch_len)
            self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
            i += batch_len
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        self.assertEqual(machine_rule_qs.count(), 6)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor
        )
        self.assertEqual(len(rule_batch), 0)
        self.assertIsNone(response_cursor)
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
        # the client received the last batch and makes another request
        batch_len = 1
        rule_batch, response_cursor4 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor3
        )
        self.assertIsNotNone(response_cursor4)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 10)
        self.assertEqual(machine_rule_qs.filter(cursor=response_cursor4).count(), batch_len)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).exclude(cursor=response_cursor4).count(), 0)
        self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
        i += batch_len
        # last batch
        rule_batch, response_cursor5 = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor4
        )
        self.assertIsNone(response_cursor5)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 11)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=False).count(), 0)
        self.assertEqual(rule_batch, [])

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
        for batch_len in (5, 1):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, [],
                response_cursor
            )
            self.assertIsNotNone(response_cursor)
            self.assertEqual(machine_rule_qs.filter(cursor=response_cursor).count(), batch_len)
            self.assertEqual(rule_batch, serialized_rules[i: i + batch_len])
            i += batch_len
        self.assertEqual(machine_rule_qs.count(), 6)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
        # last batch, never acknowleged, the client keeps making new requests without cursor
        # and getting the last unacknowlegded rule
        for i in range(2):
            rule_batch, response_cursor_post_reset = MachineRule.objects.get_next_rule_batch(
                self.enrolled_machine, []
            )
            self.assertIsNotNone(response_cursor_post_reset)
            self.assertEqual(rule_batch, [serialized_rules[-1]])
            self.assertEqual(machine_rule_qs.count(), 6)
            self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 5)
            self.assertEqual(machine_rule_qs.filter(cursor=response_cursor_post_reset).count(), 1)
        # the client acknowleges the last rule
        rule_batch, final_response_cursor = MachineRule.objects.get_next_rule_batch(
            self.enrolled_machine, [],
            response_cursor_post_reset
        )
        self.assertEqual(machine_rule_qs.count(), 6)
        self.assertEqual(machine_rule_qs.filter(cursor__isnull=True).count(), 6)
        self.assertEqual(rule_batch, [])

    def test_updated_rule(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        _, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        rule.custom_msg = "YOLO"
        rule.version = F("version") + 1
        rule.save()
        serialized_rule["custom_msg"] = rule.custom_msg
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertIsNotNone(response_cursor)
        self.assertEqual(rule_batch, [serialized_rule])
        machine_rule_qs = self.enrolled_machine.machinerule_set.all()
        self.assertEqual(machine_rule_qs.count(), 1)
        machine_rule = machine_rule_qs.first()
        self.assertEqual(machine_rule.target, target)
        self.assertEqual(machine_rule.policy, rule.policy)
        self.assertEqual(machine_rule.version, 2)
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        self.assertEqual(machine_rule_qs.count(), 1)
        self.assertEqual(machine_rule.pk, machine_rule_qs.first().pk)
        machine_rule.refresh_from_db()
        self.assertIsNone(machine_rule.cursor)
        rule_batch2, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch2, [])
        self.assertEqual(response_cursor, None)

    def test_deleted_rule(self):
        target, rule, serialized_rule = self.create_and_serialize_rule()
        _, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        rule.delete()
        serialized_rule.pop("custom_msg", None)
        serialized_rule["policy"] = "REMOVE"
        response_cursor = None
        for i in range(2):
            rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
            self.enrolled_machine.refresh_from_db()
            self.assertIsNotNone(response_cursor)
            self.assertEqual(rule_batch, [serialized_rule])
            machine_rule_qs = self.enrolled_machine.machinerule_set.all()
            self.assertEqual(machine_rule_qs.count(), 1)
            machine_rule = machine_rule_qs.first()
            self.assertEqual(machine_rule.target, target)
            self.assertEqual(machine_rule.policy, Rule.Policy.REMOVE)
            self.assertEqual(machine_rule.cursor, response_cursor)
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        self.assertEqual(machine_rule_qs.count(), 0)

    def test_scoped_rule(self):
        # rule without restrictions
        target, rule, serialized_rule = self.create_and_serialize_rule()
        _, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
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
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        # rule removed, noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, [])
        # machine tagged, rule needs to be added
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk])
        self.assertEqual(rule_batch, [serialized_rule])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk], response_cursor)
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
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk], response_cursor)
        # rule removed, noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [])
        rule.tags.set([])
        rule.excluded_tags.set(tags[-1:])
        # rule again in scope, rule needs to be added
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine,
                                                                              [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [serialized_rule])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk], response_cursor)
        # rule added noop
        rule_batch, _ = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [tags[0].pk, tags[-2].pk])
        self.assertEqual(rule_batch, [])
