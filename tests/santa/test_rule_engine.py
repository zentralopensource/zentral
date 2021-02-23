import uuid
from django.db.models import F
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.models import EnrollmentSecret, MetaBusinessUnit, Tag
from zentral.contrib.santa.models import (Bundle, Configuration, EnrolledMachine, Enrollment,
                                          MachineRule, Rule, Target, translate_rule_policy)


def new_sha256():
    return get_random_string(length=64, allowed_chars='abcdef0123456789')


class SantaRuleEngineTestCase(TestCase):
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
                                                              santa_version="1.17")
        cls.machine_serial_number2 = get_random_string(64)
        cls.enrolled_machine2 = EnrolledMachine.objects.create(enrollment=cls.enrollment,
                                                               hardware_uuid=uuid.uuid4(),
                                                               serial_number=cls.machine_serial_number2,
                                                               client_mode=Configuration.MONITOR_MODE,
                                                               santa_version="1.17")

    def create_rule(self, target_type=Target.BINARY, policy=Rule.ALLOWLIST, configuration=None):
        target = Target.objects.create(type=target_type, sha256=new_sha256())
        if configuration is None:
            configuration = self.configuration
        rule = Rule.objects.create(configuration=configuration, target=target, policy=policy)
        return target, rule

    def create_bundle_rule(self, policy=Rule.ALLOWLIST):
        bundle_target = Target.objects.create(type=Target.BUNDLE, sha256=new_sha256())
        bundle = Bundle.objects.create(
            target=bundle_target,
            path=get_random_string(78),
            executable_rel_path=get_random_string(89),
            name=get_random_string(13),
            version=get_random_string(13),
            version_str=get_random_string(12),
            binary_count=3,
        )
        for _ in range(bundle.binary_count):
            binary_target = Target.objects.create(type=Target.BINARY, sha256=new_sha256())
            bundle.binary_targets.add(binary_target)
        bundle_rule = Rule.objects.create(
            configuration=self.configuration,
            target=bundle_target,
            policy=policy
        )
        return bundle_target, bundle, bundle_rule

    def create_and_serialize_for_iter_rule(self, target_type=Target.BINARY, policy=Rule.ALLOWLIST, configuration=None):
        target, rule = self.create_rule(target_type, policy, configuration)
        result = {
            "target_id": target.pk,
            "policy": rule.policy,
            "rule_type": target.type,
            "sha256": target.sha256,
            "custom_msg": "",
            "version": rule.version,
        }
        return target, rule, result

    def create_and_serialize_rule(self, target_type=Target.BINARY, policy=Rule.ALLOWLIST, configuration=None):
        target, rule = self.create_rule(target_type, policy, configuration)
        serialized_rule = {
            "rule_type": target.type,
            "sha256": target.sha256,
            "policy": translate_rule_policy(rule.policy),
        }
        if rule.custom_msg:
            serialized_rule["custom_msg"] = rule.custom_msg
        return target, rule, serialized_rule

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

    def test_iter_tag_new_rules(self):
        target, rule, result = self.create_and_serialize_for_iter_rule()
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        rule.tags.set(tags)
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [tags[0].pk])), [result])

    def test_iter_bundle_new_rules(self):
        bundle_target, bundle, bundle_rule = self.create_bundle_rule()
        results = [{
            "target_id": binary_target.pk,
            "policy": bundle_rule.policy,
            "rule_type": binary_target.type,
            "sha256": binary_target.sha256,
            "custom_msg": "",
            "version": bundle_rule.version,
            "file_bundle_hash": bundle_target.sha256,
            "file_bundle_binary_count": bundle.binary_count,
        } for binary_target in bundle.binary_targets.all().order_by("sha256")]
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), results)
        # simulate acknowleged sync
        for binary_target in bundle.binary_targets.all():
            MachineRule.objects.create(
                enrolled_machine=self.enrolled_machine,
                target=binary_target,
                policy=bundle_rule.policy,
                version=bundle_rule.version,
            )
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), [])
        # delete the rule
        bundle_rule.delete()
        new_results = []
        for r in results:
            nr = r.copy()
            nr["policy"] = MachineRule.REMOVE
            nr.pop("custom_msg")
            nr.pop("file_bundle_hash")
            nr.pop("file_bundle_binary_count")
            new_results.append(nr)
        self.assertEqual(list(MachineRule.objects._iter_new_rules(self.enrolled_machine, [])), new_results)

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
        serialized_rules.sort(key=lambda r: r["sha256"])
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
        serialized_rules.sort(key=lambda r: r["sha256"])
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
        serialized_rules.sort(key=lambda r: r["sha256"])
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
            self.assertEqual(machine_rule.policy, MachineRule.REMOVE)
            self.assertEqual(machine_rule.cursor, response_cursor)
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        self.assertEqual(machine_rule_qs.count(), 0)

    def test_bundle_rules(self):
        # all bundle binary rules with extra attributes
        bundle_target, bundle, bundle_rule = self.create_bundle_rule()
        serialized_rules = [{
            "policy": translate_rule_policy(bundle_rule.policy),
            "rule_type": binary_target.type,
            "sha256": binary_target.sha256,
            "file_bundle_hash": bundle_target.sha256,
            "file_bundle_binary_count": bundle.binary_count,
        } for binary_target in bundle.binary_targets.all().order_by("sha256")]
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, serialized_rules)
        # noop
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, [])
        self.assertIsNone(response_cursor)
        # delete rule
        bundle_rule.delete()
        serialized_remove_rules = []
        # all bundle binary remove rules without extra attributes
        for sr in serialized_rules:
            srr = sr.copy()
            srr["policy"] = "REMOVE"
            srr.pop("file_bundle_hash")
            srr.pop("file_bundle_binary_count")
            serialized_remove_rules.append(srr)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, serialized_remove_rules)
        # noop
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        rule_batch, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        self.assertEqual(rule_batch, [])
        self.assertIsNone(response_cursor)

    def test_scoped_rule(self):
        # rule without restrictions
        target, rule, serialized_rule = self.create_and_serialize_rule()
        _, response_cursor = MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [])
        MachineRule.objects.get_next_rule_batch(self.enrolled_machine, [], response_cursor)
        # scope rule with some tags
        tags = [Tag.objects.create(name=get_random_string(32)) for _ in range(3)]
        rule.tags.set(tags)
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
