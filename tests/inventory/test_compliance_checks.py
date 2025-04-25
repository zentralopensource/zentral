from datetime import datetime
import uuid
from django.test import TestCase
from django.utils.crypto import get_random_string
from zentral.contrib.inventory.events import JMESPathCheckStatusUpdated
from zentral.contrib.inventory.models import MachineTag, Tag
from zentral.contrib.inventory.compliance_checks import jmespath_checks_cache
from zentral.core.compliance_checks.events import MachineComplianceChangeEvent
from zentral.core.compliance_checks.models import MachineStatus, Status
from .utils import force_jmespath_check


class InventoryComplianceChecksTestCase(TestCase):
    def _build_tree(self, source_name, profile_uuid, serial_number=None, platform="MACOS"):
        return {"serial_number": serial_number or get_random_string(12),
                "platform": platform,
                "source": {"module": "io.zentral.test.module",
                           "name": source_name},
                "profiles": [{"uuid": profile_uuid,
                              "identifier": get_random_string(12)},
                             {"uuid": str(uuid.uuid4()),
                              "identifier": get_random_string(12)}]}

    def test_no_tags_source_mismatch(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid)
        jmespath_check = force_jmespath_check(get_random_string(12), profile_uuid)
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 0)
        self.assertEqual(MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check).count(), 0)

    def test_no_tags_source_match_platform_match_ok(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid, serial_number, platform="IPADOS")
        jmespath_check = force_jmespath_check(source_name, profile_uuid, platforms=["IPADOS", "MACOS"])
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 2)
        event1, event2 = events
        self.assertIsInstance(event1, JMESPathCheckStatusUpdated)
        self.assertIsInstance(event2, MachineComplianceChangeEvent)
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.previous_status, None)

    def test_no_tags_source_match_platform_missmatch(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid, serial_number, platform="IPADOS")
        force_jmespath_check(source_name, profile_uuid, platforms=["IOS", "MACOS"])
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 0)

    def test_no_tags_source_match_failed(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid, serial_number)
        jmespath_check = force_jmespath_check(source_name, str(uuid.uuid4()))
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 2)
        event1, event2 = events
        self.assertIsInstance(event1, JMESPathCheckStatusUpdated)
        self.assertIsInstance(event2, MachineComplianceChangeEvent)
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.FAILED.value)
        self.assertEqual(ms.previous_status, None)

    def test_no_tags_source_match_not_boolean_unknown(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid, serial_number)
        # the following jmespath_expression does not return a boolean, but a list → UNKNOWN
        jmespath_check = force_jmespath_check(source_name, profile_uuid, jmespath_expression="profiles")
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 2)
        event1, event2 = events
        self.assertIsInstance(event1, JMESPathCheckStatusUpdated)
        self.assertIsInstance(event2, MachineComplianceChangeEvent)
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.UNKNOWN.value)
        self.assertEqual(ms.previous_status, None)

    def test_no_tags_source_match_jmespath_error_unknown(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = {"serial_number": serial_number,
                "platform": "MACOS",
                "source": {"module": get_random_string(12), "name": source_name},
                "profiles": 12345}  # will trigger a jmespath error
        jmespath_check = force_jmespath_check(source_name, profile_uuid)
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events), 2)
        event1, event2 = events
        self.assertIsInstance(event1, JMESPathCheckStatusUpdated)
        self.assertIsInstance(event2, MachineComplianceChangeEvent)
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.UNKNOWN.value)
        self.assertEqual(ms.previous_status, None)

    def test_no_tags_source_match_same_status_no_event(self):
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        tree = self._build_tree(source_name, profile_uuid, serial_number)
        jmespath_check = force_jmespath_check(source_name, profile_uuid)
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events0 = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        self.assertEqual(len(events0), 2)
        event1, event2 = events0
        self.assertIsInstance(event1, JMESPathCheckStatusUpdated)
        self.assertIsInstance(event2, MachineComplianceChangeEvent)
        events1 = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))  # use the cache
        self.assertEqual(len(events1), 0)  # second time, no event
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.previous_status, Status.OK.value)  # previous status also set

    def test_tags_no_tags_only_one_match(self):
        tags = [Tag.objects.create(name=get_random_string(12)) for _ in range(3)]
        matching_tags = tags[:2]
        non_matching_tags = tags[2:]
        profile_uuid = str(uuid.uuid4())
        source_name = get_random_string(12)
        serial_number = get_random_string(12)
        for tag in matching_tags:
            MachineTag.objects.get_or_create(serial_number=serial_number, tag=tag)
        tree = self._build_tree(source_name, profile_uuid, serial_number)
        jmespath_check_failed_no_tags = force_jmespath_check(source_name, str(uuid.uuid4()))
        jmespath_check_ok_tags = force_jmespath_check(source_name, profile_uuid, tags=matching_tags)
        jmespath_check_non_matching_tags = force_jmespath_check(source_name, profile_uuid, tags=non_matching_tags)
        jmespath_checks_cache._last_fetched_time = None  # force refresh
        events = list(jmespath_checks_cache.process_tree(tree, datetime.utcnow()))
        # two status update events for the 2 matching checks
        self.assertEqual(len(events), 3)
        for event in events[:-1]:
            if event.payload["status"] == Status.FAILED.name:
                self.assertEqual(event.payload["pk"], jmespath_check_failed_no_tags.compliance_check.pk)
                self.assertEqual(event.payload["inventory_jmespath_check"]["pk"], jmespath_check_failed_no_tags.pk)
            elif event.payload["status"] == Status.OK.name:
                self.assertEqual(event.payload["pk"], jmespath_check_ok_tags.compliance_check.pk)
                self.assertEqual(event.payload["inventory_jmespath_check"]["pk"], jmespath_check_ok_tags.pk)
                self.assertEqual(event.payload["inventory_jmespath_check"]["tags"],
                                 sorted(tag.name for tag in jmespath_check_ok_tags.tags.all()))
            else:
                raise AssertionError("Unexpected status")
        machine_compliance_event = events[-1]
        self.assertIsInstance(machine_compliance_event, MachineComplianceChangeEvent)
        self.assertEqual(machine_compliance_event.metadata.machine_serial_number, serial_number)
        self.assertEqual(machine_compliance_event.payload, {"status": Status.FAILED.name})
        # no tags, one FAILED status
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check_failed_no_tags.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.FAILED.value)
        self.assertEqual(ms.previous_status, None)
        # matching tags, one OK status
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check_ok_tags.compliance_check)
        self.assertEqual(ms_qs.count(), 1)
        ms = ms_qs.first()
        self.assertEqual(ms.serial_number, serial_number)
        self.assertEqual(ms.status, Status.OK.value)
        self.assertEqual(ms.previous_status, None)
        # missmatch, no status
        ms_qs = MachineStatus.objects.filter(compliance_check=jmespath_check_non_matching_tags.compliance_check)
        self.assertEqual(ms_qs.count(), 0)
